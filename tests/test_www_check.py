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
        with patch.object(www_check, "_fetch_text", _fetch_map(responses)), patch.object(www_check, "_REVERIFY_DELAY_SECONDS", 0):
            out = www_check.check_www_canonical("https://acme.com/")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["issue_type"], "www_variant_unreachable")
        self.assertEqual(out[0]["confidence"], "high")

    def test_transient_variant_failure_is_reverified_not_flagged(self):
        # www fails the first probe but loads on re-verify - a transient DNS/timeout blip, not a real
        # outage. It must NOT be frozen as a HIGH finding.
        calls = {}

        def _fetch(url, timeout):
            calls[url] = calls.get(url, 0) + 1
            if url == "https://www.acme.com/" and calls[url] == 1:
                return ("", url, "")  # transient failure on the first probe only
            return (200, "https://acme.com/", "<html></html>")  # both land on the bare host

        with patch.object(www_check, "_fetch_text", _fetch), patch.object(www_check, "_REVERIFY_DELAY_SECONDS", 0):
            self.assertEqual(www_check.check_www_canonical("https://acme.com/"), [])
        self.assertEqual(calls["https://www.acme.com/"], 2)  # it was re-verified once

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

    def test_platform_store_subdomain_is_not_treated_as_apex(self):
        # A store hosted on a platform (Square's *.square.site, Shopify's *.myshopify.com) reads as its
        # own "registrable" only because the platform domain is a PSL private suffix. No visitor types
        # www.<store>.square.site and the owner cannot fix the platform's DNS, so the www check must
        # skip it - matched by the ICANN (public-suffix-only) registrable domain, not the private one.
        called = []

        def _fetch(url, timeout):
            called.append(url)
            return ("", url, "")

        with patch.object(www_check, "_fetch_text", _fetch):
            self.assertEqual(www_check.check_www_canonical("https://lahistorymuseumshop.square.site/"), [])
        self.assertEqual(called, [])  # skipped before any network probe

    def test_service_subdomain_is_not_treated_as_apex(self):
        # A site served from a subdomain (foundation.sfcc.edu, whose registrable domain is sfcc.edu).
        # "www." prepended to a subdomain -> www.foundation.sfcc.edu is not an address any visitor
        # types, so its non-existence is expected, not a finding. The check must skip a non-apex host
        # before it probes anything.
        called = []

        def _fetch(url, timeout):
            called.append(url)
            return ("", url, "")

        with patch.object(www_check, "_fetch_text", _fetch):
            self.assertEqual(www_check.check_www_canonical("https://foundation.sfcc.edu/"), [])
        self.assertEqual(called, [])  # skipped before any network probe


if __name__ == "__main__":
    unittest.main()
