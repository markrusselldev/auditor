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
from urllib.parse import urlsplit

from auditor.ai_visibility import _fetch_text


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
    # Skip anything we cannot reason about: localhost, bare IPs, single-label hosts.
    if not bare or "." not in bare or _is_ip(bare) or host not in (bare, "www." + bare):
        return []
    www = "www." + bare

    bare_ok, bare_final = _reach(_fetch_text(f"{scheme}://{bare}/", timeout))
    www_ok, www_final = _reach(_fetch_text(f"{scheme}://{www}/", timeout))

    if not bare_ok and not www_ok:
        return []  # both down: that is the homepage check's story, not this one

    if bare_ok and not www_ok:
        return [_unreachable(homepage, f"{scheme}://{www}/", www, bare, "the www version of your address")]
    if www_ok and not bare_ok:
        return [_unreachable(homepage, f"{scheme}://{bare}/", bare, www, "your address without www")]

    # Both load. If they do not resolve to the same canonical host, there is no redirect between them.
    if www_final != bare_final:
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
