import unittest

from auditor.web.ratelimit import DailyCap, DomainCap, RateLimiter


class TestRateLimiter(unittest.TestCase):
    def test_allows_up_to_limit_then_blocks(self):
        limiter = RateLimiter(per_ip=3, window_seconds=600)
        for _ in range(3):
            allowed, _ = limiter.check("1.2.3.4", now=100.0)
            self.assertTrue(allowed)
        allowed, retry = limiter.check("1.2.3.4", now=100.0)
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)

    def test_window_resets_after_expiry(self):
        limiter = RateLimiter(per_ip=1, window_seconds=600)
        self.assertTrue(limiter.check("ip", now=0.0)[0])
        self.assertFalse(limiter.check("ip", now=100.0)[0])
        self.assertTrue(limiter.check("ip", now=601.0)[0])

    def test_ips_are_independent(self):
        limiter = RateLimiter(per_ip=1, window_seconds=600)
        self.assertTrue(limiter.check("a", now=0.0)[0])
        self.assertTrue(limiter.check("b", now=0.0)[0])

    def test_concurrency_slots(self):
        limiter = RateLimiter(max_concurrent=1)
        self.assertTrue(limiter.acquire_slot())
        self.assertFalse(limiter.acquire_slot())
        limiter.release_slot()
        self.assertTrue(limiter.acquire_slot())


class TestDailyCap(unittest.TestCase):
    def test_consumes_up_to_cap_then_refuses(self):
        cap = DailyCap(max_per_day=2)
        self.assertTrue(cap.try_consume(now=100.0))
        self.assertTrue(cap.try_consume(now=100.0))
        self.assertFalse(cap.try_consume(now=100.0))

    def test_rolls_off_after_the_window(self):
        cap = DailyCap(max_per_day=1, window_seconds=86400)
        self.assertTrue(cap.try_consume(now=0.0))
        self.assertFalse(cap.try_consume(now=86400.0))
        self.assertTrue(cap.try_consume(now=86401.0))


class TestDomainCap(unittest.TestCase):
    def test_per_domain_ceiling_then_refuses(self):
        cap = DomainCap(max_per_domain=1)
        self.assertTrue(cap.try_consume("example.com", now=0.0))
        self.assertFalse(cap.try_consume("example.com", now=0.0))

    def test_domains_are_independent_buckets(self):
        cap = DomainCap(max_per_domain=1)
        self.assertTrue(cap.try_consume("foo.wixsite.com", now=0.0))
        self.assertTrue(cap.try_consume("bar.wixsite.com", now=0.0))  # separate tenant, own budget

    def test_empty_key_never_granted(self):
        self.assertFalse(DomainCap(max_per_domain=5).try_consume("", now=0.0))

    def test_rolls_off_after_window(self):
        cap = DomainCap(max_per_domain=1, window_seconds=86400)
        self.assertTrue(cap.try_consume("example.com", now=0.0))
        self.assertFalse(cap.try_consume("example.com", now=86400.0))
        self.assertTrue(cap.try_consume("example.com", now=86401.0))


if __name__ == "__main__":
    unittest.main()
