"""SSRF egress guard: our own HTTP client must refuse to fetch private, loopback, link-local, or
cloud-metadata addresses, so a user-supplied URL (or a redirect it follows) cannot reach the
instance's internal network or the Cloud Run metadata endpoint. This is the app-side belt behind
the deploy-side Smokescreen proxy."""

import unittest
from unittest.mock import patch

from auditor import security


class HostGuardTest(unittest.TestCase):
    def setUp(self):
        # The guard is default-DENY in production; force that posture regardless of the test env's
        # AUDITOR_ALLOW_PRIVATE_HOSTS (which the suite sets so loopback fixtures work).
        self._patch = patch.dict("os.environ", {"AUDITOR_ALLOW_PRIVATE_HOSTS": "0"})
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def test_public_ip_allowed(self):
        self.assertFalse(security.host_is_blocked("8.8.8.8"))

    def test_loopback_blocked(self):
        self.assertTrue(security.host_is_blocked("127.0.0.1"))

    def test_private_range_blocked(self):
        self.assertTrue(security.host_is_blocked("10.0.0.1"))
        self.assertTrue(security.host_is_blocked("192.168.1.1"))

    def test_cloud_metadata_blocked(self):
        self.assertTrue(security.host_is_blocked("169.254.169.254"))

    def test_empty_host_blocked(self):
        self.assertTrue(security.host_is_blocked(""))

    def test_allow_toggle_permits_loopback(self):
        with patch.dict("os.environ", {"AUDITOR_ALLOW_PRIVATE_HOSTS": "1"}):
            self.assertFalse(security.host_is_blocked("127.0.0.1"))


class RegistrableDomainTest(unittest.TestCase):
    def test_plain_domain(self):
        self.assertEqual(security.registrable_domain("https://shop.example.com/x"), "example.com")

    def test_multi_label_public_suffix(self):
        self.assertEqual(security.registrable_domain("https://a.b.example.co.uk/"), "example.co.uk")

    def test_shared_host_keys_per_tenant(self):
        # The PSL private section: distinct tenants on a shared host are distinct buckets, so one
        # tenant cannot exhaust another's deep-test budget.
        self.assertEqual(security.registrable_domain("foo.wixsite.com"), "foo.wixsite.com")
        self.assertNotEqual(
            security.registrable_domain("foo.wixsite.com"),
            security.registrable_domain("bar.wixsite.com"),
        )

    def test_bare_host_without_scheme(self):
        self.assertEqual(security.registrable_domain("shop.example.com"), "example.com")

    def test_ip_and_localhost_have_no_registrable_domain(self):
        self.assertEqual(security.registrable_domain("10.0.0.1"), "")
        self.assertEqual(security.registrable_domain("localhost"), "")


class BrowserHardeningTest(unittest.TestCase):
    def test_sandbox_on_by_default_and_never_disabled(self):
        with patch.dict("os.environ", {}) as _:
            import os
            os.environ.pop("AUDITOR_CHROMIUM_SANDBOX", None)
            kwargs = security.browser_launch_kwargs()
        self.assertTrue(kwargs["chromium_sandbox"])
        self.assertTrue(kwargs["headless"])
        # Must never weaken the two real protections.
        self.assertNotIn("--no-sandbox", kwargs["args"])
        self.assertFalse(any("IsolateOrigins" in a or "site-per-process" in a for a in kwargs["args"]))

    def test_sandbox_can_be_disabled_for_incapable_environments(self):
        with patch.dict("os.environ", {"AUDITOR_CHROMIUM_SANDBOX": "0"}):
            self.assertFalse(security.browser_launch_kwargs()["chromium_sandbox"])

    def test_extra_args_are_appended(self):
        kwargs = security.browser_launch_kwargs(("--foo",))
        self.assertIn("--foo", kwargs["args"])
        self.assertIn("--disable-dev-shm-usage", kwargs["args"])

    def test_no_proxy_key_when_unset(self):
        with patch.dict("os.environ", {}) as _:
            import os
            os.environ.pop("AUDITOR_EGRESS_PROXY", None)
            self.assertNotIn("proxy", security.browser_launch_kwargs())

    def test_egress_proxy_pins_the_browser_when_set(self):
        with patch.dict("os.environ", {"AUDITOR_EGRESS_PROXY": "http://smokescreen:4750"}):
            self.assertEqual(
                security.browser_launch_kwargs()["proxy"], {"server": "http://smokescreen:4750"}
            )


class GuardedFetchTest(unittest.TestCase):
    def test_blocked_host_returns_transport_error_shape(self):
        # _fetch_text must refuse a blocked host with its ("", url, "") transport-error shape,
        # never actually opening the connection.
        from auditor.ai_visibility import _fetch_text
        with patch.dict("os.environ", {"AUDITOR_ALLOW_PRIVATE_HOSTS": "0"}), \
             patch("auditor.ai_visibility.urllib.request.urlopen") as opener:
            status, final, body = _fetch_text("http://169.254.169.254/latest/meta-data/")
        opener.assert_not_called()
        self.assertEqual((status, body), ("", ""))


if __name__ == "__main__":
    unittest.main()
