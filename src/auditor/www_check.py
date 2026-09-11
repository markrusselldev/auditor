"""www vs non-www canonical health.

A correctly configured site serves ONE canonical host and redirects the other to it (www to the
bare host, or the bare host to www). Two externally-visible failures a visitor can reproduce:

  - The alternate variant does not load at all (no DNS, SSL error, connection refused, 5xx). A
    visitor who types that version hits a wall instead of the site. HIGH.
  - Both variants return a page independently, neither redirecting to the other. Search engines see
    two copies (split ranking, duplicate content), and cookies/logins set on one host do not apply
    to the other. MEDIUM.

Both hosts are probed with the shared HTTP client (SSRF-guarded, follows redirects); we compare
where each one lands. A finding only fires when at least one variant loads, so a wholly-down site
(already caught by the homepage check) is not double-reported here.
"""

from __future__ import annotations

import ipaddress
import time
from urllib.parse import urlsplit

# A brief pause before re-verifying a failed fetch: an immediate retry often hits the same cached
# DNS-negative result or momentary congestion, so a short delay materially improves the odds of
# clearing a transient blip (retry-with-backoff practice) without meaningfully slowing a scan.
_REVERIFY_DELAY_SECONDS = 2.0

from auditor.ai_visibility import _fetch_text
from auditor.security import registrable_domain


def _bare(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _reach(result: tuple) -> tuple[bool, str]:
    """(loaded ok, final hostname) for a _fetch_text result."""
    status, final, _body = result
    ok = isinstance(status, int) and 200 <= status < 400
    return ok, (urlsplit(final).hostname or "").lower()


def check_www_canonical(homepage: str, timeout: float = 10.0) -> list[dict]:
    parts = urlsplit(homepage)
    host = (parts.hostname or "").lower()
    scheme = parts.scheme or "https"
    bare = _bare(host)
    # Skip anything we cannot reason about: localhost, bare IPs, single-label hosts. Also skip a site
    # served from a subdomain (bare is not the registrable apex): the www/non-www convention pairs the
    # apex with its www host (example.com <-> www.example.com). Prepending "www." to a subdomain like
    # foundation.sfcc.edu yields www.foundation.sfcc.edu, an address no visitor types, whose absence is
    # expected rather than a failure.
    if not bare or "." not in bare or _is_ip(bare) or host not in (bare, "www." + bare) or bare != registrable_domain(bare, include_private=False):
        return []
    www = "www." + bare

    bare_ok, bare_final = _reach(_fetch_text(f"{scheme}://{bare}/", timeout))
    www_ok, www_final = _reach(_fetch_text(f"{scheme}://{www}/", timeout))

    if not bare_ok and not www_ok:
        return []  # both down: that is the homepage check's story, not this one

    # A single failed fetch can be a transient DNS/timeout/network blip, not a real outage. Before
    # freezing "this variant is unreachable" as a HIGH finding, re-verify the failed variant ONCE
    # (one extra fetch, only when a failure was seen). Only a repeat failure is emitted.
    if bare_ok and not www_ok:
        time.sleep(_REVERIFY_DELAY_SECONDS)
        www_ok, www_final = _reach(_fetch_text(f"{scheme}://{www}/", timeout))
        if not www_ok:
            return [_unreachable(homepage, f"{scheme}://{www}/", www, bare, "the www version of your address")]
    if www_ok and not bare_ok:
        time.sleep(_REVERIFY_DELAY_SECONDS)
        bare_ok, bare_final = _reach(_fetch_text(f"{scheme}://{bare}/", timeout))
        if not bare_ok:
            return [_unreachable(homepage, f"{scheme}://{bare}/", bare, www, "your address without www")]

    # Both load (possibly after re-verify). If they do not resolve to the same canonical host, there
    # is no redirect between them.
    if bare_ok and www_ok and www_final != bare_final:
        return [{
            "issue_type": "www_no_canonical_redirect",
            "confidence": "medium",
            "source_url": homepage,
            "failed_url": f"{scheme}://{www}/",
            "evidence": f"Both {bare} and {www} load your site without redirecting to one address. "
                        f"Search engines see two copies of your site, which splits your ranking, and "
                        f"logins or cookies set on one address do not carry to the other.",
            "revenue_relevant": False,
        }]
    return []


def _unreachable(homepage: str, failed_url: str, dead: str, live: str, typed: str) -> dict:
    return {
        "issue_type": "www_variant_unreachable",
        "confidence": "high",
        "source_url": homepage,
        "failed_url": failed_url,
        "evidence": f"{dead} does not load, but {live} does. A visitor who types {typed} hits an "
                    f"error instead of reaching your site.",
        "revenue_relevant": True,
    }
