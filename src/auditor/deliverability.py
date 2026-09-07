"""Email-deliverability DNS checks: the other half of silent form failure.

A contact form that emails the owner can pass the browser submit test (the request fires and reaches
a working destination) and still never land, because the mail is spam-foldered or rejected for
failing sender authentication. That half is not visible in the browser; it lives in the domain's DNS.

We check the two records that are checkable from outside with certainty:
  - SPF   (a TXT record on the domain starting "v=spf1")
  - DMARC (a TXT record at _dmarc.<domain> starting "v=DMARC1")
DKIM cannot be checked blind: it lives at <selector>._domainkey.<domain> and the selector is chosen
by the sender, so absence at the selectors we guess proves nothing. We best-effort a couple of common
selectors and report DKIM as present or unknown, and NEVER flag it as missing.

Honest boundary (kept in the finding text): a missing SPF/DMARC record is a real, reproducible
deliverability and spoofing RISK, not proof this particular form fails. Many forms are sent by a
third-party form host from its own authenticated domain, so the site's own records may not govern
them. We report the risk, we do not claim the form is broken.

DNS is queried over DNS-over-HTTPS (dns.google) so there is no new dependency and nothing to install.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request

_DOH_URL = "https://dns.google/resolve"
# Checked only to CONFIRM DKIM when present; never used to assert it is missing.
_COMMON_DKIM_SELECTORS = ("google", "default")


def _doh_txt(name: str, timeout: float) -> list[str]:
    """Return the TXT record strings for `name`, or [] on any failure (a DNS hiccup must not fail
    the scan). Concatenated character-strings are joined, surrounding quotes stripped."""
    query = _DOH_URL + "?" + urllib.parse.urlencode({"name": name, "type": "TXT"})
    request = urllib.request.Request(query, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return []
    out: list[str] = []
    for answer in data.get("Answer", []):
        if answer.get("type") != 16:  # 16 = TXT
            continue
        raw = str(answer.get("data", "")).strip()
        # DoH returns TXT as one or more quoted character-strings, e.g. "\"v=spf1\" \" include:...\"".
        out.append(raw.replace('" "', "").strip('"'))
    return out


def check_deliverability(domain: str, timeout: float = 10.0) -> dict:
    """Look up SPF / DMARC / (best-effort) DKIM for `domain`. Returns a JSON-serializable summary."""
    if not domain:
        return {"checked": False}
    spf = next((r for r in _doh_txt(domain, timeout) if r.lower().startswith("v=spf1")), "")
    dmarc = next(
        (r for r in _doh_txt("_dmarc." + domain, timeout) if r.lower().startswith("v=dmarc1")), ""
    )
    dkim_present: bool | None = None
    for selector in _COMMON_DKIM_SELECTORS:
        records = _doh_txt(f"{selector}._domainkey.{domain}", timeout)
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
            dkim_present = True
            break
    # The DMARC policy (p=) is what a receiving server DOES with mail that fails authentication:
    # none = only report, quarantine = send to spam, reject = block. "none" is monitor-only.
    policy_match = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", dmarc, re.I)
    return {
        "checked": True,
        "domain": domain,
        "spf": {"present": bool(spf), "record": spf},
        "dmarc": {"present": bool(dmarc), "record": dmarc,
                  "policy": policy_match.group(1).lower() if policy_match else ""},
        # None = could not confirm from common selectors (NOT proof of absence).
        "dkim": {"present": dkim_present},
    }


def deliverability_findings(summary: dict) -> list[dict]:
    """Turn a check_deliverability summary into findings. Only the certain gaps (no SPF, no DMARC)
    are reported, each as a medium-confidence deliverability RISK, never as a confirmed form failure.
    DKIM is never flagged as missing."""
    if not summary.get("checked"):
        return []
    domain = summary.get("domain", "your domain")
    out: list[dict] = []
    if not summary["dmarc"]["present"]:
        out.append({
            "issue_type": "missing_dmarc",
            "confidence": "medium",
            "source_url": domain,
            "failed_url": "_dmarc." + domain,
            "evidence": f"{domain} has no DMARC record. Mail sent from your domain, including a form "
                        f"notification, is easier to spoof and more likely to be filtered as spam, so "
                        f"a message a visitor triggers can quietly fail to reach you. This is a DNS "
                        f"and deliverability risk, not proof this form is broken.",
            "revenue_relevant": False,
        })
    elif summary["dmarc"].get("policy") == "none":
        out.append({
            "issue_type": "dmarc_monitoring_only",
            "confidence": "low",
            "source_url": domain,
            "failed_url": "_dmarc." + domain,
            "evidence": f"{domain} has DMARC, but its policy is p=none, which only monitors and "
                        f"reports. Mail that forges your domain is not blocked or spam-filtered by "
                        f"receiving servers, so spoofing protection is off. Moving to p=quarantine "
                        f"then p=reject, once your legitimate senders pass, turns it on. This is a "
                        f"deliverability and anti-spoofing risk, not proof this form is broken.",
            "revenue_relevant": False,
        })
    if not summary["spf"]["present"]:
        out.append({
            "issue_type": "missing_spf",
            "confidence": "medium",
            "source_url": domain,
            "failed_url": domain,
            "evidence": f"{domain} has no SPF record, so receiving mail servers cannot verify which "
                        f"servers may send for your domain. Mail from your domain is more likely to be "
                        f"rejected or spam-filtered. This is a DNS and deliverability risk, not proof "
                        f"this form is broken.",
            "revenue_relevant": False,
        })
    return out
