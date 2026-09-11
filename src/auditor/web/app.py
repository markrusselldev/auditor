"""The HTTP service. Stdlib only: one page, one scan endpoint, health check, per-IP limiting.

Dependency-free on purpose (a lean image and a small surface). Each request runs on its own thread,
so the engine's internal asyncio.run works without an event-loop clash.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from auditor import __version__, geo, security
from auditor.scan_one import normalize_url, scan_url
from auditor.web.analytics import NullSink, build_record, safe_record, sink_from_env
from auditor.web.cache import TTLCache
from auditor.web.ratelimit import DailyCap, DomainCap, RateLimiter

try:
    from importlib.metadata import version as _pkg_version
    APP_VERSION: str | None = _pkg_version("auditor")
except Exception:
    APP_VERSION = os.environ.get("AUDITOR_VERSION") or None

# Private, IP-free scan analytics (auditor.web.analytics). Off unless AUDITOR_ANALYTICS=local|gcs, in
# which case one JSON record per scan is written for the owner's later analysis. Built once at import.
SINK = sink_from_env()

STATIC_DIR = Path(__file__).parent / "static"
MAX_BODY_BYTES = 4096
SCAN_TIMEOUT = float(os.environ.get("AUDITOR_SCAN_TIMEOUT", "20"))
# Local/testing escape hatch: turns OFF the result cache and every abuse cap so a site can be
# re-scanned repeatedly. NEVER set in production (like AUDITOR_ALLOW_PRIVATE_HOSTS); default off.
DISABLE_LIMITS = os.environ.get("AUDITOR_DISABLE_LIMITS", "").strip().lower() in {"1", "true", "yes", "on"}
_UNLIMITED = 10 ** 9
# Passive per-target result cache: a repeat scan of the same URL within the
# window returns the saved report instead of rescanning. 24h default; ships as config.
CACHE_TTL_SECONDS = float(os.environ.get("AUDITOR_CACHE_TTL_SECONDS", str(24 * 3600)))
CACHE = TTLCache(ttl_seconds=CACHE_TTL_SECONDS, disabled=DISABLE_LIMITS)
# Global rolling-24h ceiling on real scans: the app-side backstop to the provider's hard spend cap.
# Only cache MISSES (actual engine runs) consume it. Ships as config.
DAILY_SCAN_CAP = int(os.environ.get("AUDITOR_DAILY_SCAN_CAP", "1000"))
DAILY = DailyCap(max_per_day=_UNLIMITED if DISABLE_LIMITS else DAILY_SCAN_CAP)
# The consent-gated deep form test (fills+submits) is hard-capped low PER REGISTRABLE DOMAIN so it
# can never be aimed at one site in volume. Ships as config.
DEEP_TEST_PER_DOMAIN_CAP = int(os.environ.get("AUDITOR_DEEP_TEST_PER_DOMAIN_CAP", "5"))
DEEP_CAP = DomainCap(max_per_domain=_UNLIMITED if DISABLE_LIMITS else DEEP_TEST_PER_DOMAIN_CAP)
# Passive per-registrable-domain scan cap: bounds how many DISTINCT pages of one site get a real
# scan in 24h (the per-URL cache only stops repeats of the SAME url). Stops one person walking a
# whole site page by page. Ships as config.
PER_DOMAIN_SCAN_CAP = int(os.environ.get("AUDITOR_PER_DOMAIN_SCAN_CAP", "10"))
DOMAIN_CAP = DomainCap(max_per_domain=_UNLIMITED if DISABLE_LIMITS else PER_DOMAIN_SCAN_CAP)


def _client_ip(handler: BaseHTTPRequestHandler) -> str:
    forwarded = handler.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0] if handler.client_address else "unknown"


class Handler(BaseHTTPRequestHandler):
    server_version = f"AuditorWeb/{__version__}"
    limiter: RateLimiter = RateLimiter(per_ip=_UNLIMITED) if DISABLE_LIMITS else RateLimiter()

    def log_message(self, fmt: str, *args) -> None:  # to stdout, one line, Cloud-Run-friendly
        sys.stdout.write(f"{self.address_string()} - {fmt % args}\n")
        sys.stdout.flush()

    def _send_json(self, status: int, payload: dict, extra_headers: dict | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._serve_static("index.html", "text/html; charset=utf-8")
        elif self.path == "/health":
            self._send_json(200, {"status": "ok"})
        elif re.fullmatch(r"/fonts/[A-Za-z0-9._-]+\.woff2", self.path):
            # Self-hosted fonts, same origin: no external Google Fonts call (blocked by the egress
            # proxy anyway) and no font swap. The strict pattern blocks path traversal.
            self._serve_static(self.path.lstrip("/"), "font/woff2",
                               {"Cache-Control": "public, max-age=31536000, immutable"})
        else:
            self._send_json(404, {"error": "not_found"})

    def _serve_static(self, name: str, content_type: str, extra: dict | None = None) -> None:
        path = STATIC_DIR / name
        if not path.exists():
            self._send_json(404, {"error": "not_found"})
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/scan":
            self._send_json(404, {"error": "not_found"})
            return
        ip = _client_ip(self)
        allowed, retry_after = self.limiter.check(ip)
        if not allowed:
            self._send_json(429, {"error": "rate_limited",
                                  "message": "Too many scans from your address. Try again shortly."},
                            {"Retry-After": str(int(retry_after) + 1)})
            return
        try:
            url, own_site = self._read_request()
            cache_key = normalize_url(url)
        except ValueError as exc:
            self._send_json(400, {"error": "bad_request", "message": str(exc)})
            return
        # Owner (deep) scans bypass the public cache in BOTH directions: a public visitor must never
        # be served an owner's deep report, and an owner scan must never overwrite the public entry.
        if not own_site:
            cached = CACHE.get(cache_key)
            if cached is not None:
                self._record_scan(url=url, own_site=own_site, cached=True, outcome="ok",
                                  meta=cached.get("_analytics", {}))
                payload = {k: v for k, v in cached.items() if k != "_analytics"}
                self._send_json(200, {**payload, "cached": True}, {"X-Auditor-Cache": "hit"})
                return
        if not self.limiter.acquire_slot():
            self._send_json(503, {"error": "busy",
                                  "message": "The scanner is at capacity. Please try again in a moment."})
            return
        # Passive per-domain cap: bound distinct-page scans of one site per 24h (the per-URL cache
        # only stops exact repeats). Consumed only for a real scan, so cache hits above stay free.
        domain = security.registrable_domain(url)
        if domain and not DOMAIN_CAP.try_consume(domain):
            self.limiter.release_slot()
            self._send_json(429, {"error": "site_daily_limit",
                                  "message": "You have reached today's free scans for this site. "
                                             "A fresh rescan is part of the pro version."})
            return
        # Spend a daily credit only now that we hold a slot and will actually scan, so slot
        # contention never burns the global budget.
        if not DAILY.try_consume():
            self.limiter.release_slot()
            self._send_json(503, {"error": "daily_capacity",
                                  "message": "The scanner has reached today's capacity. Please try again tomorrow."})
            return
        # Honor the deep-test consent only within the per-registrable-domain hard cap; over it, the
        # scan still runs, just without the fill-and-submit step.
        deep = own_site and DEEP_CAP.try_consume(security.registrable_domain(url))
        started = time.monotonic()
        try:
            report = scan_url(url, timeout=SCAN_TIMEOUT, own_site=deep)
            elapsed = int((time.monotonic() - started) * 1000)
            outcome = "unreachable" if report.get("unreachable") else "ok"
            self._record_scan(url=url, own_site=own_site, cached=False, outcome=outcome,
                              meta=report.get("_analytics", {}), duration_ms=elapsed)
            # Do not cache an unreachable result: the site may recover, and a retry should re-probe.
            if not own_site and not report.get("unreachable"):
                CACHE.put(cache_key, report)
            payload = {k: v for k, v in report.items() if k != "_analytics"}
            self._send_json(200, {**payload, "cached": False}, {"X-Auditor-Cache": "miss"})
        except ValueError as exc:
            self._record_scan(url=url, own_site=own_site, cached=False, outcome="error", meta={},
                              error_kind="bad_request", duration_ms=int((time.monotonic() - started) * 1000))
            self._send_json(400, {"error": "bad_request", "message": str(exc)})
        except Exception as exc:  # a scan failure must be a clean 500, never a crashed worker
            self._record_scan(url=url, own_site=own_site, cached=False, outcome="error", meta={},
                              error_kind="scan_failed", duration_ms=int((time.monotonic() - started) * 1000))
            traceback.print_exc()
            self._send_json(500, {"error": "scan_failed", "message": f"The scan could not complete: {exc}"})
        finally:
            self.limiter.release_slot()

    def _record_scan(self, *, url: str, own_site: bool, cached: bool, outcome: str,
                     meta: dict, error_kind: str | None = None, duration_ms: int = 0) -> None:
        """Write one non-PII analytics record for this scan. No-op when analytics is off.

        The client IP is read here only to derive a coarse country/network type and is never stored
        (see auditor.geo). Recording is best-effort and can never affect the response.
        """
        if isinstance(SINK, NullSink):
            return
        try:
            geo_info = geo.lookup(_client_ip(self))
        except Exception:
            geo_info = None
        scope = "single_page" if urlsplit(url).path.strip("/") else "homepage"
        record = build_record(
            domain=security.registrable_domain(url) or "",
            url_scope=scope,
            own_site=own_site,
            overall_score=meta.get("overall_score"),
            overall_grade=meta.get("overall_grade"),
            total_findings=meta.get("total_findings"),
            finding_counts=meta.get("finding_counts") or {},
            category_scores=meta.get("category_scores") or {},
            duration_ms=duration_ms,
            platform=meta.get("platform"),
            pages_crawled=meta.get("pages_crawled"),
            checks=meta.get("checks"),
            phase_ms=meta.get("phase_ms"),
            outcome=outcome,
            error_kind=error_kind,
            llm_provider=meta.get("llm_provider"),
            llm_offline=meta.get("llm_offline"),
            cached=cached,
            geo=geo_info,
            user_agent=self.headers.get("User-Agent"),
            referrer=self.headers.get("Referer"),
            accept_language=self.headers.get("Accept-Language"),
            app_version=APP_VERSION,
        )
        safe_record(SINK, record)

    def _read_request(self) -> tuple[str, bool]:
        """Parse the scan body: the required url and the optional own_site consent flag."""
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("Send a JSON body of {\"url\": \"...\"}")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Body must be valid JSON") from exc
        url = data.get("url") if isinstance(data, dict) else None
        if not url or not isinstance(url, str):
            raise ValueError("A \"url\" field is required")
        return url, bool(data.get("own_site"))


def build_server(host: str = "0.0.0.0", port: int | None = None) -> ThreadingHTTPServer:
    port = port if port is not None else int(os.environ.get("PORT", "8080"))
    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    server = build_server()
    host, port = server.server_address[:2]
    if DISABLE_LIMITS:
        # Loud, so an accidental production start with the testing escape hatch on cannot hide.
        print("WARNING: AUDITOR_DISABLE_LIMITS is ON - cache and all abuse caps are OFF. "
              "This is for local testing only; never run it in production.", file=sys.stderr, flush=True)
    print(f"auditor web service listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
