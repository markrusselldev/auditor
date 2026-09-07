import unittest

from auditor.llm.offline_provider import OfflineProvider
from auditor.report import (
    _category_for,
    _collapse,
    build_compact,
    first_impression,
    overall_score,
    score_categories,
    write_report,
)


class CategoryAndCollapseTest(unittest.TestCase):
    def test_new_findings_get_their_own_category(self):
        self.assertEqual(_category_for("accessibility_color-contrast"), "Accessibility")
        self.assertEqual(_category_for("dmarc_monitoring_only"), "Email deliverability")
        self.assertEqual(_category_for("missing_spf"), "Email deliverability")
        self.assertEqual(_category_for("slow_largest_content"), "Performance")
        self.assertEqual(_category_for("layout_shift"), "Performance")
        self.assertEqual(_category_for("mixed_http_resource"), "Security")
        self.assertEqual(_category_for("page_http_failure"), "Links & reachability")

    def test_collapse_keeps_full_evidence(self):
        long_ev = "A" * 180 + " Moving to the next sentence that must survive, not be cut mid-word."
        out = _collapse([{"issue_type": "dmarc_monitoring_only", "confidence": "low", "evidence": long_ev}])
        self.assertEqual(out[0]["evidence"], long_ev)  # not truncated to 200


def _ai(schema=True, crawlers=True, llms=True):
    return {
        "llms_txt": {"present": llms, "status": "llms.txt" if llms else "No llms.txt"},
        "schema_org": {"present": schema, "status": "schema.org present" if schema else "none"},
        "ai_crawler_access": {"present": crawlers, "status": "allowed" if crawlers else "blocks GPTBot"},
        "what_ai_says": [{"model": "offline", "has_reliable_knowledge": False, "summary": "n/a", "confidence": "none"}],
    }


class TestReport(unittest.TestCase):
    def test_category_mapping_and_scoring(self):
        findings = [
            {"issue_type": "mobile_horizontal_overflow", "confidence": "high", "failed_url": "u", "evidence": "e"},
            {"issue_type": "broken_image", "confidence": "high", "failed_url": "u2", "evidence": "e2"},
        ]
        cats = score_categories(findings, _ai())
        by_name = {c["name"]: c for c in cats}
        self.assertIn("AI visibility", by_name)
        self.assertEqual(by_name["Mobile experience"]["finding_count"], 1)
        self.assertEqual(by_name["Mobile experience"]["score"], 75)  # 100 - 25 (one high)
        self.assertEqual(by_name["Images & assets"]["score"], 75)

    def test_repeated_identical_findings_collapse_and_score_once(self):
        # One header form reported on 6 pages is one issue, not six: it must not tank the score 6x.
        findings = [
            {"issue_type": "interface_broken", "confidence": "medium",
             "source_url": f"https://x/p{i}", "failed_url": f"https://x/p{i}",
             "evidence": "Visible form lacks fields or a submission control"}
            for i in range(6)
        ]
        cats = {c["name"]: c for c in score_categories(findings, _ai())}
        rev = cats["Revenue paths"]
        self.assertEqual(rev["finding_count"], 6)
        self.assertEqual(rev["unique_issue_count"], 1)
        self.assertEqual(rev["score"], 88)  # 100 - one medium (12), not 6x12
        self.assertEqual(rev["findings"][0]["count"], 6)

    def test_distinct_evidence_stays_separate(self):
        findings = [
            {"issue_type": "interface_broken", "confidence": "medium", "failed_url": "u1", "evidence": "form A broken"},
            {"issue_type": "interface_broken", "confidence": "medium", "failed_url": "u2", "evidence": "form B broken"},
        ]
        cats = {c["name"]: c for c in score_categories(findings, _ai())}
        self.assertEqual(cats["Revenue paths"]["unique_issue_count"], 2)

    def test_ai_visibility_deducts_for_missing_checks(self):
        cats = score_categories([], _ai(schema=False, crawlers=False, llms=False))
        ai = next(c for c in cats if c["name"] == "AI visibility")
        self.assertEqual(ai["score"], 100 - 25 - 30 - 15)

    def test_clean_site_scores_high(self):
        cats = score_categories([], _ai())
        self.assertEqual(overall_score(cats), 100)

    def test_overall_weights_visitor_categories_double(self):
        # One core F among many clean secondaries must land LOWER than a flat average would.
        cats = [{"name": "Revenue paths", "score": 0},
                {"name": "Performance", "score": 100}, {"name": "Security", "score": 100},
                {"name": "Email deliverability", "score": 100}]
        flat = round(sum(c["score"] for c in cats) / len(cats))  # 75
        self.assertEqual(flat, 75)
        self.assertLess(overall_score(cats), flat)  # weighted: 0*2 + 300 = 300 / 5 = 60

    def test_untested_category_is_not_scored_or_averaged(self):
        # The accessibility check did not run and found nothing: "not tested", not a perfect score.
        cats = score_categories([], _ai(), checks={"accessibility": "no_data"})
        by_name = {c["name"]: c for c in cats}
        self.assertFalse(by_name["Accessibility"]["tested"])
        self.assertIsNone(by_name["Accessibility"]["score"])
        self.assertIsNone(by_name["Accessibility"]["grade"])
        self.assertTrue(by_name["Performance"]["tested"])  # no signal for it -> tested
        # The null-score category is excluded from the overall, so it neither inflates nor deflates it.
        self.assertEqual(overall_score(cats), 100)

    def test_gated_check_with_a_finding_is_still_tested(self):
        # A finding proves the check ran, even if its health signal says no_data.
        findings = [{"issue_type": "accessibility_image-alt", "confidence": "medium",
                     "failed_url": "u", "evidence": "e"}]
        cats = {c["name"]: c for c in score_categories(findings, _ai(), checks={"accessibility": "no_data"})}
        self.assertTrue(cats["Accessibility"]["tested"])
        self.assertIsNotNone(cats["Accessibility"]["score"])

    def test_offline_report_is_readable_and_names_worst(self):
        findings = [{"issue_type": "mobile_horizontal_overflow", "confidence": "high",
                     "failed_url": "https://x/p", "evidence": "590px overflow"}]
        compact = build_compact("Acme", "https://x", findings, _ai(schema=False))
        report = write_report(OfflineProvider(), compact)
        self.assertIn("headline", report)
        self.assertTrue(report["top_fixes"])
        self.assertLessEqual(len(report["top_fixes"]), 5)

    def test_offline_report_clean_site_says_good_shape(self):
        compact = build_compact("Acme", "https://x", [], _ai())
        report = write_report(OfflineProvider(), compact)
        self.assertIn("No externally visible failures", report["headline"])

    def test_first_impression_offline_is_unavailable_not_invented(self):
        result = first_impression(OfflineProvider(), b"\x89PNG-fake", "Acme", "https://x")
        self.assertTrue(result["insufficient_information"])
        self.assertEqual(result["glaring_issues"], [])

    def test_first_impression_without_screenshot_is_unavailable(self):
        result = first_impression(OfflineProvider(), None, "Acme", "https://x")
        self.assertTrue(result["insufficient_information"])

    def test_compact_has_no_raw_html(self):
        compact = build_compact("Acme", "https://x", [], _ai())
        blob = str(compact)
        self.assertNotIn("<html", blob)
        self.assertIn("overall_score", compact)


if __name__ == "__main__":
    unittest.main()
