"""Web endpoint wiring: the passive result cache serves a repeat scan of the same URL without
re-running the engine."""

import json
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

from auditor.web import app as webapp
from auditor.web.cache import TTLCache
from auditor.web.ratelimit import DailyCap, DomainCap, RateLimiter


def _post(base: str, url: str, own_site: bool = False):
    body = {"url": url}
    if own_site:
        body["own_site"] = True
    req = urllib.request.Request(
        base + "/scan", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers), json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), json.loads(exc.read())


class CacheWiringTest(unittest.TestCase):
    def setUp(self):
        webapp.Handler.limiter = RateLimiter(per_ip=100)
        self.cache_patch = patch.object(webapp, "CACHE", TTLCache(ttl_seconds=1000))
        self.cache_patch.start()
        self.scan = MagicMock(return_value={"url": "https://acme.test/", "overall_score": 91})
        self.scan_patch = patch.object(webapp, "scan_url", self.scan)
        self.scan_patch.start()
        self.server = webapp.build_server(host="127.0.0.1", port=0)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.scan_patch.stop()
        self.cache_patch.stop()

    def test_repeat_scan_is_served_from_cache(self):
        s1, h1, b1 = _post(self.base, "acme.test")
        s2, h2, b2 = _post(self.base, "acme.test")
        self.assertEqual((s1, s2), (200, 200))
        self.scan.assert_called_once()  # the engine ran once; the repeat came from cache
        self.assertEqual(h2.get("X-Auditor-Cache"), "hit")
        # Same report both times, marked fresh then cached so the page can say so.
        self.assertFalse(b1["cached"])
        self.assertTrue(b2["cached"])
        self.assertEqual({k: v for k, v in b1.items() if k != "cached"},
                         {k: v for k, v in b2.items() if k != "cached"})

    def test_disabled_cache_rescans_every_time(self):
        with patch.object(webapp, "CACHE", TTLCache(ttl_seconds=1000, disabled=True)):
            _post(self.base, "acme.test")
            _post(self.base, "acme.test")
        self.assertEqual(self.scan.call_count, 2)  # no cache: the engine ran both times


class StaticServingTest(unittest.TestCase):
    """Self-hosted fonts are served same-origin with a woff2 type; path traversal is refused."""

    def setUp(self):
        self.server = webapp.build_server(host="127.0.0.1", port=0)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()

    def test_font_is_served_as_woff2(self):
        req = urllib.request.Request(self.base + "/fonts/gabarito-latin-wght.woff2")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Content-Type"), "font/woff2")
            self.assertGreater(len(resp.read()), 1000)

    def test_traversal_and_unknown_paths_404(self):
        for bad in ["/fonts/../app.py", "/fonts/evil.woff2", "/secret.txt"]:
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(self.base + bad)
            self.assertEqual(cm.exception.code, 404)


class DeepTestGatingTest(unittest.TestCase):
    """own_site (the 'this is my site' consent) plumbs through to scan_url, but the deep test is
    hard-capped per registrable domain and its results bypass the public cache."""

    def setUp(self):
        webapp.Handler.limiter = RateLimiter(per_ip=100)
        self.calls = []
        self.scan = MagicMock(side_effect=lambda url, **kw: self.calls.append(kw.get("own_site")) or
                              {"url": url, "own_site_ran": kw.get("own_site")})
        self.patches = [
            patch.object(webapp, "CACHE", TTLCache(ttl_seconds=1000)),
            patch.object(webapp, "DAILY", DailyCap(max_per_day=100)),
            patch.object(webapp, "DEEP_CAP", DomainCap(max_per_domain=1)),
            patch.object(webapp, "DOMAIN_CAP", DomainCap(max_per_domain=1000)),
            patch.object(webapp, "scan_url", self.scan),
        ]
        for p in self.patches:
            p.start()
        self.server = webapp.build_server(host="127.0.0.1", port=0)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        for p in self.patches:
            p.stop()

    def test_consent_plumbs_through_within_cap(self):
        _post(self.base, "acme.com", own_site=True)
        self.assertEqual(self.calls, [True])

    def test_deep_test_capped_per_registrable_domain(self):
        _post(self.base, "acme.com", own_site=True)          # spends the one deep credit -> True
        _post(self.base, "www.acme.com", own_site=True)      # same registrable domain -> over cap
        self.assertEqual(self.calls, [True, False])

    def test_owner_scan_is_not_cached_for_the_public_path(self):
        _post(self.base, "acme.com", own_site=True)
        _status, headers, _body = _post(self.base, "acme.com")  # public follow-up
        self.assertEqual(headers.get("X-Auditor-Cache"), "miss")  # not served from the owner scan
        self.assertEqual(self.calls, [True, False])  # ran twice; second was public (own_site False)


class PerDomainScanCapTest(unittest.TestCase):
    """Distinct pages of one registrable domain are capped per 24h, so one site cannot be walked
    page by page past the free limit; over it, a clear pro-upsell message."""

    def setUp(self):
        webapp.Handler.limiter = RateLimiter(per_ip=100)
        self.patches = [
            patch.object(webapp, "CACHE", TTLCache(ttl_seconds=1000)),
            patch.object(webapp, "DAILY", DailyCap(max_per_day=100)),
            patch.object(webapp, "DOMAIN_CAP", DomainCap(max_per_domain=1)),
            patch.object(webapp, "scan_url",
                         MagicMock(side_effect=lambda url, **kw: {"url": url, "overall_score": 80})),
        ]
        for p in self.patches:
            p.start()
        self.server = webapp.build_server(host="127.0.0.1", port=0)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        for p in self.patches:
            p.stop()

    def test_distinct_pages_of_a_domain_are_capped(self):
        s1, _, _ = _post(self.base, "example.com/a")           # first page of example.com
        s2, _, b2 = _post(self.base, "example.com/b")          # second distinct page, same domain
        self.assertEqual(s1, 200)
        self.assertEqual(s2, 429)
        self.assertEqual(b2.get("error"), "site_daily_limit")


class DailyCapWiringTest(unittest.TestCase):
    def setUp(self):
        webapp.Handler.limiter = RateLimiter(per_ip=100)
        self.patches = [
            patch.object(webapp, "CACHE", TTLCache(ttl_seconds=1000)),
            patch.object(webapp, "DAILY", DailyCap(max_per_day=1)),
            patch.object(webapp, "scan_url",
                         MagicMock(side_effect=lambda url, **kw: {"url": url, "overall_score": 80})),
        ]
        for p in self.patches:
            p.start()
        self.server = webapp.build_server(host="127.0.0.1", port=0)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        for p in self.patches:
            p.stop()

    def test_scans_past_the_daily_cap_are_refused(self):
        # Distinct URLs so the cache never serves them: the first scan spends the only credit; the
        # second must hit the global daily backstop with a 503.
        s1, _, _ = _post(self.base, "one.test")
        s2, _, b2 = _post(self.base, "two.test")
        self.assertEqual(s1, 200)
        self.assertEqual(s2, 503)
        self.assertEqual(b2.get("error"), "daily_capacity")


if __name__ == "__main__":
    unittest.main()
