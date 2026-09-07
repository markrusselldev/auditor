"""The passive result cache: a repeat within the TTL returns the saved value; past it, a miss."""

import unittest

from auditor.web.cache import TTLCache


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class TTLCacheTest(unittest.TestCase):
    def test_hit_within_ttl(self):
        clock = FakeClock()
        cache = TTLCache(ttl_seconds=100, clock=clock)
        cache.put("https://acme.test/", {"score": 91})
        clock.now += 50
        self.assertEqual(cache.get("https://acme.test/"), {"score": 91})

    def test_miss_after_expiry(self):
        clock = FakeClock()
        cache = TTLCache(ttl_seconds=100, clock=clock)
        cache.put("https://acme.test/", {"score": 91})
        clock.now += 101
        self.assertIsNone(cache.get("https://acme.test/"))

    def test_unknown_key_misses(self):
        self.assertIsNone(TTLCache(ttl_seconds=100).get("nope"))

    def test_disabled_always_misses(self):
        cache = TTLCache(ttl_seconds=1000, disabled=True)
        cache.put("k", {"v": 1})
        self.assertIsNone(cache.get("k"))  # never stores, always a miss

    def test_lru_eviction_past_capacity(self):
        cache = TTLCache(ttl_seconds=100, max_entries=2)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.get("a")          # touch 'a' so 'b' is now least-recently-used
        cache.put("c", 3)       # over capacity -> evict the LRU, which is 'b'
        self.assertEqual(cache.get("a"), 1)
        self.assertIsNone(cache.get("b"))
        self.assertEqual(cache.get("c"), 3)


if __name__ == "__main__":
    unittest.main()
