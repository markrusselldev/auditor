"""Accessibility findings from axe results (axe run itself is exercised live, not here): severity
ordering, capping, and the honest never-claim-compliance disclosure."""

import unittest

from auditor import accessibility


def _axe(violations):
    return {"violations": violations}


class AccessibilityTest(unittest.TestCase):
    def test_no_result_no_findings(self):
        self.assertEqual(accessibility.accessibility_findings(None), [])
        self.assertEqual(accessibility.accessibility_findings(_axe([])), [])

    def test_findings_sorted_by_impact_and_capped(self):
        v = [{"id": f"rule{i}", "impact": imp, "help": f"Fix {i}", "nodes": i + 1}
             for i, imp in enumerate(["minor", "critical", "moderate", "serious"] * 3)]
        out = accessibility.accessibility_findings(_axe(v), "https://acme.com/")
        self.assertEqual(len(out), 8)  # capped
        self.assertEqual(out[0]["confidence"], "high")  # critical/serious first
        self.assertTrue(all(f["issue_type"].startswith("accessibility_") for f in out))

    def test_impact_maps_to_confidence(self):
        out = accessibility.accessibility_findings(_axe([
            {"id": "a", "impact": "critical", "help": "A", "nodes": 1},
            {"id": "b", "impact": "moderate", "help": "B", "nodes": 2},
            {"id": "c", "impact": "minor", "help": "C", "nodes": 3},
        ]))
        by_type = {f["issue_type"]: f["confidence"] for f in out}
        self.assertEqual(by_type["accessibility_a"], "high")
        self.assertEqual(by_type["accessibility_b"], "medium")
        self.assertEqual(by_type["accessibility_c"], "low")

    def test_summary_always_carries_the_honest_disclosure(self):
        ran = accessibility.accessibility_summary(_axe([{"id": "x", "impact": "serious", "help": "H", "nodes": 1}]))
        self.assertTrue(ran["ran"])
        self.assertEqual(ran["violation_count"], 1)
        self.assertIn("not a guarantee", ran["disclosure"])
        self.assertIn("assistive technology", ran["disclosure"])
        self.assertFalse(accessibility.accessibility_summary(None)["ran"])

    def test_vendored_axe_script_loads(self):
        js = accessibility.axe_script()
        self.assertIn("axe", js)
        self.assertGreater(len(js), 100000)  # the real minified engine


if __name__ == "__main__":
    unittest.main()
