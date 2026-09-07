"""www vs non-www canonical checks (HTTP mocked): flag a broken variant or two independent copies,
stay quiet when one properly redirects to the other."""

import unittest
from unittest.mock import patch

from auditor import www_check


def _fetch_map(responses):
    """responses: {url: (status, final_url, body)}; default is a transport error."""
    def _fetch(url, timeout):
        return responses.get(url, ("", url, ""))
    return _fetch


class WwwCheckTest(unittest.TestCase):
    def test_proper_redirect_no_finding(self):
        # www 301s to the bare host: both probes land on the bare host.
        responses = {
            "https://acme.com/": (200, "https://acme.com/", "<html></html>"),
            "https://www.acme.com/": (200, "https://acme.com/", "<html></html>"),
        }
        with patch.object(www_check, "_fetch_text", _fetch_map(responses)):
            self.assertEqual(www_check.check_www_canonical("https://acme.com/"), [])

    def test_alternate_variant_unreachable_is_high(self):
        # bare loads, www fails to load at all.
        responses = {"https://acme.com/": (200, "https://acme.com/", "<html></html>")}
        with patch.object(www_check, "_fetch_text", _fetch_map(responses)):
            out = www_check.check_www_canonical("https://acme.com/")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["issue_type"], "www_variant_unreachable")
        self.assertEqual(out[0]["confidence"], "high")

    def test_both_independent_is_medium(self):
        # Both serve 200 on their own host, neither redirects to the other.
        responses = {
            "https://acme.com/": (200, "https://acme.com/", "<html></html>"),
            "https://www.acme.com/": (200, "https://www.acme.com/", "<html></html>"),
        }
        with patch.object(www_check, "_fetch_text", _fetch_map(responses)):
            out = www_check.check_www_canonical("https://www.acme.com/")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["issue_type"], "www_no_canonical_redirect")
        self.assertEqual(out[0]["confidence"], "medium")

    def test_both_down_no_finding(self):
        with patch.object(www_check, "_fetch_text", _fetch_map({})):  # nothing loads
            self.assertEqual(www_check.check_www_canonical("https://acme.com/"), [])

    def test_localhost_and_ip_skipped(self):
        self.assertEqual(www_check.check_www_canonical("http://localhost:8080/"), [])
        self.assertEqual(www_check.check_www_canonical("http://127.0.0.1/"), [])


if __name__ == "__main__":
    unittest.main()
