"""scan_one orchestration wiring.

These tests drive the real scan_url assembly with the heavy engine (browser crawl, vision, LLM)
stubbed, so they exercise how the static per-page detectors reach the report:

  - mixed_content findings are REAL findings: they must land in the scored categories.
  - page_basics items are hygiene: they must reach the report (under "basics") but must NEVER be
    counted as failure findings (never appear in a scored category).
"""

import dataclasses
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from auditor import scan_one

# An https page (mixed content only exists on https) with one active-mixed resource and several
# missing table-stakes basics. title + h1 are present, so only meta-description, canonical, and
# image-alt should be flagged as basics.
PAGE_URL = "https://acme.test/"
PAGE_HTML = """<!doctype html><html><head>
<title>Acme</title>
<script src="http://cdn.example.com/app.js"></script>
</head><body>
<h1>Welcome</h1>
<img src="/logo.png">
</body></html>"""

_AI = {
    "llms_txt": {"present": False, "status": ""},
    "schema_org": {"present": False, "status": ""},
    "ai_crawler_access": {"present": False, "status": ""},
    "what_ai_says": [],
}


class _FakeProvider:
    name = "offline-test"

    def complete_json(self, *, system, user, schema, image_png=None, temperature=0.2, offline_fallback=None):
        return offline_fallback


@dataclasses.dataclass
class _Row:
    issue_type: str
    confidence: str = "medium"
    source_url: str = PAGE_URL
    failed_url: str = PAGE_URL
    evidence: str = "engine finding"


def _fake_audit_for(html, findings=()):
    def _fake_audit(*args, **kwargs):
        coverage = SimpleNamespace(coverage_status="sufficient_coverage")
        summary = SimpleNamespace(scan_outcome="findings_present")
        return 1, list(findings), [], coverage, summary, [(PAGE_URL, html)]
    return _fake_audit


_DELIVERABILITY_OK = {"checked": True, "domain": "acme.test",
                      "spf": {"present": True, "record": "v=spf1 ~all"},
                      "dmarc": {"present": True, "record": "v=DMARC1; p=none"},
                      "dkim": {"present": True}}


def _run_scan(html, *, own_site=False, verify=None, reachability=None, deliverability=None,
              engine_findings=()):
    """Drive scan_url with the heavy engine (crawl, vision, LLM), both browser passes, and DNS stubbed."""
    verify = verify if verify is not None else MagicMock(return_value=[])
    reachability = reachability if reachability is not None else MagicMock(return_value=([], []))
    deliverability = deliverability if deliverability is not None else _DELIVERABILITY_OK
    with patch("auditor.v2._audit_organization", _fake_audit_for(html, engine_findings)), \
         patch("auditor.scan_one._fetch_text", return_value=(200, PAGE_URL, "")), \
         patch("auditor.scan_one.run_ai_visibility", return_value=_AI), \
         patch("auditor.scan_one._vision_screenshot", return_value=(None, {})), \
         patch("auditor.scan_one.verify_revenue_forms", verify), \
         patch("auditor.scan_one.run_browser_validation", reachability), \
         patch("auditor.scan_one.check_deliverability", return_value=deliverability), \
         patch("auditor.scan_one.check_www_canonical", return_value=[]), \
         patch("auditor.scan_one.get_report_provider", return_value=_FakeProvider()):
        report = scan_one.scan_url("acme.test", own_site=own_site)
    return report, verify, reachability


# A page carrying a contact form (empty action = JS-handled, so detect_forms does no network probe).
CONTACT_HTML = """<!doctype html><html><head><title>Acme</title></head><body>
<h1>Contact</h1>
<form><input name="email" type="email"><textarea name="message"></textarea>
<button type="submit">Send</button></form>
</body></html>"""


class NormalizeUrlTest(unittest.TestCase):
    """Input validation: accept only http(s) with a real host; reject malformed input cleanly."""

    def test_prepends_https_and_keeps_scheme(self):
        self.assertEqual(scan_one.normalize_url("example.com"), "https://example.com")
        self.assertEqual(scan_one.normalize_url("http://example.com/x"), "http://example.com/x")

    def test_malformed_port_rejected_cleanly(self):
        with self.assertRaises(ValueError):
            scan_one.normalize_url("http://localhost:9000)")  # the stray-paren typo

    def test_non_http_schemes_rejected(self):
        for u in ["file:///etc/passwd", "ftp://x.com", "javascript:alert(1)", "data:text/html,x"]:
            with self.assertRaises(ValueError):
                scan_one.normalize_url(u)

    def test_no_host_and_empty_and_too_long_rejected(self):
        for u in ["", "   ", "http://", "https:///path", "http://x.com/" + "a" * 3000]:
            with self.assertRaises(ValueError):
                scan_one.normalize_url(u)

    def test_gibberish_and_fake_tld_rejected(self):
        # No registrable domain (no valid public suffix): a single label or a made-up TLD is not a
        # site we can scan. This is the "bhghjghjghjghj scored an A" bug. The suite runs with private
        # hosts allowed (conftest), so force it off here to test the production rule.
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"AUDITOR_ALLOW_PRIVATE_HOSTS": "0"}):
            for u in ["bhghjghjghjghj", "asdf", "notarealtld.zzzzz"]:
                with self.assertRaises(ValueError):
                    scan_one.normalize_url(u)

    def test_real_domain_accepted(self):
        # A syntactically real domain passes even if it may not resolve; reachability is decided later.
        self.assertEqual(scan_one.normalize_url("bhghjghjghjghj.com"), "https://bhghjghjghjghj.com")

    def test_localhost_allowed_only_under_private_flag(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"AUDITOR_ALLOW_PRIVATE_HOSTS": "0"}):
            with self.assertRaises(ValueError):
                scan_one.normalize_url("http://localhost:8080")
        with mock.patch.dict(os.environ, {"AUDITOR_ALLOW_PRIVATE_HOSTS": "1"}):
            self.assertEqual(scan_one.normalize_url("http://localhost:8080"), "http://localhost:8080")


class ScanOneWiringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report, _, _ = _run_scan(PAGE_HTML)

    def _category_findings(self):
        return [f for c in self.report["categories"] for f in c.get("findings", [])]

    def test_mixed_content_is_a_scored_finding(self):
        types = {f.get("issue_type") for f in self._category_findings()}
        self.assertIn("mixed_http_resource", types, self.report["categories"])

    def test_basics_reach_the_report(self):
        basics = self.report["basics"]
        types = {b["issue_type"] for b in basics}
        self.assertEqual(
            types, {"missing_meta_description", "missing_canonical", "images_missing_alt"}, basics
        )
        self.assertTrue(all(b["category"] == "basics" for b in basics), basics)

    def test_basics_never_counted_as_failures(self):
        basics_types = {"missing_meta_description", "missing_canonical", "images_missing_alt",
                        "missing_page_title", "missing_h1"}
        scored_types = {f.get("issue_type") for f in self._category_findings()}
        self.assertEqual(scored_types & basics_types, set(), scored_types)


class RevenueConsentTest(unittest.TestCase):
    """The deep form test fills and submits, so it is consent-gated: OFF by default (public path),
    ON only when the caller sets own_site (the 'this is my site' box)."""

    def test_default_public_path_does_not_run_the_deep_test(self):
        report, verify, _ = _run_scan(CONTACT_HTML)  # own_site defaults False
        verify.assert_not_called()
        self.assertFalse(report["revenue_verify"]["ran"], report["revenue_verify"])

    def test_consent_runs_the_deep_test_on_form_pages(self):
        finding = {
            "issue_type": "revenue_submit_no_request", "confidence": "high",
            "source_url": PAGE_URL, "failed_url": PAGE_URL,
            "evidence": "The form's submit fires no request.", "revenue_relevant": True,
        }
        verify = MagicMock(return_value=[finding])
        report, verify, _ = _run_scan(CONTACT_HTML, own_site=True, verify=verify)

        verify.assert_called_once()
        self.assertEqual(verify.call_args.kwargs.get("own_site"), True)
        self.assertEqual(verify.call_args.args[0], [PAGE_URL])

        self.assertTrue(report["revenue_verify"]["ran"])
        scored = [f for c in report["categories"] for f in c.get("findings", [])]
        self.assertIn("revenue_submit_no_request", {f.get("issue_type") for f in scored}, scored)

    def test_consent_surfaces_the_honest_disclosure(self):
        report, _, _ = _run_scan(CONTACT_HTML, own_site=True)
        self.assertEqual(
            report["revenue_verify"]["disclosure"],
            "confirms your form is wired to a reachable destination; does not send real data, "
            "so does not confirm the server accepts it.",
        )


def _evidence(category, interaction_result, result):
    from auditor.browser_verifier import BrowserEvidence
    return BrowserEvidence(
        organization="Acme", homepage=PAGE_URL, source_page=PAGE_URL, category=category,
        visible_control=category.title(), control_type="a", original_target=PAGE_URL + category,
        resulting_url=PAGE_URL + category, interaction_result=interaction_result,
        main_document_status=404 if result == "confirmed_broken" else 200,
        visible_error_text="", browser_or_network_error="", screenshot_path="",
        verification_result=result, evidence=f"{category} link {result}",
    )


class ControlReachabilityTest(unittest.TestCase):
    """The stable browser_verifier control-reachability (donate/book/contact links resolve) runs in
    the web scan path, not only in deep_revenue batch mode. Only confirmed-broken controls become
    findings; functional/manual-review controls do not."""

    def test_confirmed_broken_control_becomes_a_finding(self):
        rows = [
            _evidence("donation", "same-tab", "confirmed_broken"),
            _evidence("contact", "same-tab", "appears_functional"),
            _evidence("ticket", "same-tab", "needs_manual_review"),
        ]
        reachability = MagicMock(return_value=(rows, []))
        report, _, reachability = _run_scan(PAGE_HTML, reachability=reachability)

        reachability.assert_called_once()
        scored = [f for c in report["categories"] for f in c.get("findings", [])]
        types = {f.get("issue_type") for f in scored}
        self.assertIn("revenue_path_donation_same-tab", types, scored)
        self.assertNotIn("revenue_path_contact_same-tab", types, scored)
        self.assertNotIn("revenue_path_ticket_same-tab", types, scored)

    def test_finding_names_the_actual_control(self):
        # visible_control "Donate Now" must surface in the finding, not a generic label.
        import dataclasses
        row = dataclasses.replace(_evidence("donation", "same-tab", "confirmed_broken"),
                                  visible_control="Donate Now")
        report, _, _ = _run_scan(PAGE_HTML, reachability=MagicMock(return_value=([row], [])))
        donation = next(f for c in report["categories"] for f in c.get("findings", [])
                        if f.get("issue_type") == "revenue_path_donation_same-tab")
        self.assertIn('"Donate Now"', donation["evidence"], donation)

    def test_reachability_failure_never_sinks_the_scan(self):
        reachability = MagicMock(side_effect=RuntimeError("playwright exploded"))
        report, _, _ = _run_scan(PAGE_HTML, reachability=reachability)
        self.assertIn("categories", report)


class ScopeByUrlTest(unittest.TestCase):
    """The entered URL sets the free scope: a homepage crawls a few top pages; a specific page URL
    scans only that one page."""

    def _scope_for(self, url):
        captured = {}

        def _rec(*a, **k):
            captured["max_pages"] = k.get("max_pages")
            captured["max_depth"] = k.get("max_depth")
            return _fake_audit_for(PAGE_HTML)(*a, **k)

        with patch("auditor.v2._audit_organization", _rec), \
             patch("auditor.scan_one._fetch_text", return_value=(200, PAGE_URL, "")), \
             patch("auditor.scan_one.run_ai_visibility", return_value=_AI), \
             patch("auditor.scan_one._vision_screenshot", return_value=(None, {})), \
             patch("auditor.scan_one.verify_revenue_forms", MagicMock(return_value=[])), \
             patch("auditor.scan_one.run_browser_validation", MagicMock(return_value=([], []))), \
             patch("auditor.scan_one.check_deliverability", return_value=_DELIVERABILITY_OK), \
             patch("auditor.scan_one.get_report_provider", return_value=_FakeProvider()):
            scan_one.scan_url(url)
        return captured

    def test_homepage_scans_a_few_pages(self):
        scope = self._scope_for("acme.test")
        self.assertEqual(scope["max_pages"], scan_one.FREE_HOMEPAGE_MAX_PAGES)
        self.assertEqual(scope["max_depth"], 1)

    def test_specific_page_scans_only_that_page(self):
        scope = self._scope_for("acme.test/pricing")
        self.assertEqual((scope["max_pages"], scope["max_depth"]), (1, 0))


class WebNoiseSuppressionTest(unittest.TestCase):
    """Developer-oriented / redundant engine findings are kept out of the owner-facing web report,
    while a real reachability failure stays (and lands in Links & reachability)."""

    def test_console_and_error_text_suppressed_but_http_failure_kept(self):
        rows = [_Row("serious_console_error"), _Row("visible_site_failure"), _Row("page_http_failure"),
                _Row("interface_usable_submission_not_tested")]
        report, _, _ = _run_scan(PAGE_HTML, engine_findings=rows)
        types = {f.get("issue_type") for c in report["categories"] for f in c.get("findings", [])}
        self.assertNotIn("serious_console_error", types)
        self.assertNotIn("visible_site_failure", types)
        self.assertNotIn("interface_usable_submission_not_tested", types)
        self.assertIn("page_http_failure", types)
        links = next(c for c in report["categories"] if c["name"] == "Links & reachability")
        self.assertIn("page_http_failure", {f["issue_type"] for f in links["findings"]})


class DeliverabilityWiringTest(unittest.TestCase):
    """SPF/DMARC deliverability reaches the report: the summary is surfaced, and a missing DMARC
    becomes a scored finding."""

    def test_summary_reaches_the_report(self):
        report, _, _ = _run_scan(PAGE_HTML)
        self.assertIn("deliverability", report)
        self.assertTrue(report["deliverability"]["checked"])

    def test_missing_dmarc_becomes_a_finding(self):
        bad = {"checked": True, "domain": "acme.test",
               "spf": {"present": False, "record": ""},
               "dmarc": {"present": False, "record": ""}, "dkim": {"present": None}}
        report, _, _ = _run_scan(PAGE_HTML, deliverability=bad)
        types = {f.get("issue_type") for c in report["categories"] for f in c.get("findings", [])}
        self.assertIn("missing_dmarc", types)
        self.assertIn("missing_spf", types)


if __name__ == "__main__":
    unittest.main()
