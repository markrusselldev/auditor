"""Performance findings: flag only poor Core Web Vitals, stay quiet on good ones."""

import unittest

from auditor.performance import performance_findings


class PerformanceTest(unittest.TestCase):
    def test_good_vitals_no_findings(self):
        good = {"lcp_ms": 1800, "cls": 0.02, "fcp_ms": 1200, "ttfb_ms": 300}
        self.assertEqual(performance_findings(good), [])

    def test_poor_lcp_flagged(self):
        out = performance_findings({"lcp_ms": 6200, "cls": 0.0, "ttfb_ms": 100})
        self.assertEqual([f["issue_type"] for f in out], ["slow_largest_content"])
        self.assertIn("6.2s", out[0]["evidence"])

    def test_poor_cls_and_ttfb_flagged(self):
        out = performance_findings({"lcp_ms": 1000, "cls": 0.4, "ttfb_ms": 2500})
        types = {f["issue_type"] for f in out}
        self.assertEqual(types, {"layout_shift", "slow_server_response"})

    def test_borderline_not_flagged(self):
        # "needs improvement" band (between good and poor) is deliberately not flagged.
        out = performance_findings({"lcp_ms": 3000, "cls": 0.15, "ttfb_ms": 1000})
        self.assertEqual(out, [])

    def test_missing_vitals_no_findings(self):
        self.assertEqual(performance_findings(None), [])
        self.assertEqual(performance_findings({}), [])


if __name__ == "__main__":
    unittest.main()
