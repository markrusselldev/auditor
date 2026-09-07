"""App-side egress security. Central home for the pre-launch guardrails.

SSRF egress guard (this module's first job): our own HTTP client must never fetch a private,
loopback, link-local, or cloud-metadata address, because the scan target is a user-supplied URL and
a hostile one (or a redirect it follows) could otherwise reach the instance's internal network or
the Cloud Run metadata endpoint (169.254.169.254). Best practice (OWASP SSRF Prevention Cheat Sheet):
resolve the host and check EVERY resolved IP against non-global ranges, and re-apply that check to
every redirect hop - a first-hop allowlist is bypassed by a redirect or DNS rebinding.

We use `ipaddress.is_global`: it is False for private (RFC1918), loopback, link-local (incl. the
metadata IP), reserved, unspecified, and shared/CGNAT (100.64/10) space, and it resolves
IPv4-mapped IPv6 through to the underlying v4 address - so "block unless is_global" is the single
robust rule. This is the app-side belt; the deploy-side Smokescreen egress proxy is the braces.

All limits and toggles read from the environment so numbers ship as config, tuned at deploy.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import urllib.request
from urllib.parse import urlsplit

import tldextract


class SecurityError(Exception):
    """Raised when a request would egress to a blocked destination."""


# Registrable-domain keying for the per-domain deep-test cap. suffix_list_urls=() uses the snapshot
# bundled in the package (no network in a locked-down container), cache_dir=None avoids disk, and
# include_psl_private_domains=True consults the PSL private section so shared hosts key per tenant -
# foo.wixsite.com and bar.wixsite.com are DIFFERENT buckets, not one wixsite.com bucket.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True,
)


def registrable_domain(url_or_host: str) -> str:
    """The registrable (top-domain-under-public-suffix) key for a URL or bare host, or "" when there
    is none (a bare IP, localhost, or unparseable input)."""
    if not url_or_host:
        return ""
    host = urlsplit(url_or_host if "://" in url_or_host else "//" + url_or_host).hostname or ""
    return _EXTRACT(host).top_domain_under_public_suffix or ""


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def allow_private_hosts() -> bool:
    """Escape hatch for local development and the test suite (which scans 127.0.0.1 fixtures).

    OFF by default, so production is default-DENY. The deploy sets this to 0/unset; tests set it to
    1 (see tests/conftest.py).
    """
    return _env_flag("AUDITOR_ALLOW_PRIVATE_HOSTS", default=False)


def _ip_is_blocked(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return True  # unparseable: refuse rather than guess
    # is_global is False for every range we must not reach (private, loopback, link-local incl. the
    # metadata IP, reserved, unspecified, multicast, CGNAT), and follows IPv4-mapped IPv6 to its v4.
    return not ip.is_global


def host_is_blocked(host: str | None) -> bool:
    """True if `host` must not be fetched: it has no name, fails to resolve, or ANY of its resolved
    addresses is non-global. Honors the allow-private escape hatch for local/test use."""
    if allow_private_hosts():
        return False
    if not host:
        return True
    # An IP literal is checked directly; a name is resolved to every A/AAAA it yields, and blocked
    # if any one is non-global (a single internal answer is enough to abort).
    try:
        ipaddress.ip_address(host)
        return _ip_is_blocked(host)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return True  # cannot resolve -> cannot verify -> refuse
    return any(_ip_is_blocked(info[4][0]) for info in infos)


# Browser hardening for rendering untrusted pages. Best practice (Playwright /
# Chromium security guidance): KEEP the Chromium sandbox on (the real wall between a hostile page and
# the host) - never pass --no-sandbox - and do NOT disable Site Isolation. These flags only trim
# background chatter and attack surface; they do not weaken those two protections. The browser's
# network universe is narrowed separately by the SSRF guard here plus the deploy-side egress proxy.
_HARDENING_ARGS = (
    "--disable-dev-shm-usage",       # small /dev/shm in containers -> use /tmp, avoids crashes
    "--disable-background-networking",  # no telemetry / update / variations pings
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-sync",
    "--no-first-run",
    "--mute-audio",
)


def chromium_sandbox_enabled() -> bool:
    """Chromium sandbox ON by default (the primary defense when rendering untrusted pages). A
    containerized host that cannot initialize Chromium's own sandbox - including this project's
    Cloud Run image (see the Dockerfile) - sets AUDITOR_CHROMIUM_SANDBOX=0 and relies on the
    container platform's own isolation (gVisor) instead."""
    return _env_flag("AUDITOR_CHROMIUM_SANDBOX", default=True)


def egress_proxy() -> str:
    """The egress-filtering proxy (Stripe Smokescreen) the browser routes through in front of the
    open internet. Set AUDITOR_EGRESS_PROXY at deploy; empty in dev/test so the browser connects
    directly. It covers the BROWSER specifically - the one surface the app-side SSRF guard cannot
    reach. The tool's own urllib fetches are covered by that guard, not this proxy (routing urllib
    through HTTPS_PROXY as well would break the instance's metadata and GCS auth)."""
    return os.environ.get("AUDITOR_EGRESS_PROXY", "").strip()


def browser_launch_kwargs(extra_args: tuple[str, ...] = ()) -> dict:
    """Hardened kwargs for chromium.launch(): headless, sandbox kept on, background chatter trimmed,
    and (when configured) egress pinned through the filtering proxy. Callers add only environment
    discovery (e.g. executable_path), never security-weakening flags."""
    kwargs = {
        "headless": True,
        "chromium_sandbox": chromium_sandbox_enabled(),
        "args": [*_HARDENING_ARGS, *extra_args],
    }
    proxy = egress_proxy()
    if proxy:
        kwargs["proxy"] = {"server": proxy}
    return kwargs


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-apply the host guard to every redirect target; abort the whole request on a blocked hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if host_is_blocked(urlsplit(newurl).hostname):
            raise SecurityError(f"redirect to blocked host: {urlsplit(newurl).hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_GuardedRedirectHandler())


def urlopen_guarded(request, timeout: float):
    """urlopen with redirect-hop validation. Callers must still check the INITIAL host with
    host_is_blocked() before building the request; this covers only the redirect chain."""
    return _OPENER.open(request, timeout=timeout)
