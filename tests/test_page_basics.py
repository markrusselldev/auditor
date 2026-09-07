"""Table-stakes basics: present on a well-formed page (no items), flagged when missing - and always
tagged as 'basics'/info so they never count as failures."""
import unittest

from auditor.page_basics import basics_findings

GOOD = """<!doctype html><html><head>
<title>Acme Bakery - Fresh Bread Daily</title>
<meta name="description" content="Acme Bakery bakes fresh sourdough every morning in Santa Fe.">
<link rel="canonical" href="https://acme.test/">
</head><body>
<h1>Welcome to Acme Bakery</h1>
<img src="/loaf.jpg" alt="A fresh sourdough loaf">
</body></html>"""

BAD = """<!doctype html><html><head></head><body>
<p>no title, no description, no h1, no canonical</p>
<img src="/a.jpg" alt=""><img src="/b.jpg"><img src="/c.jpg">
</body></html>"""


class PageBasicsTest(unittest.TestCase):
    def test_well_formed_page_has_no_basics_gaps(self):
        self.assertEqual(basics_findings([("https://acme.test/", GOOD)]), [])

    def test_missing_basics_are_all_flagged(self):
        items = basics_findings([("https://acme.test/", BAD)])
        types = {i["issue_type"] for i in items}
        self.assertEqual(
            types,
            {"missing_page_title", "missing_meta_description", "missing_h1",
             "images_missing_alt", "missing_canonical"},
        )

    def test_only_missing_alt_images_are_counted(self):
        # BAD has 3 imgs: one alt="" (decorative, fine) and two with no alt attribute.
        item = next(i for i in basics_findings([("u", BAD)]) if i["issue_type"] == "images_missing_alt")
        self.assertIn("2 of 3", item["evidence"])

    def test_basics_never_count_as_failures(self):
        for i in basics_findings([("u", BAD)]):
            self.assertEqual(i["category"], "basics")
            self.assertEqual(i["confidence"], "info")
            self.assertFalse(i["revenue_relevant"])


if __name__ == "__main__":
    unittest.main()
