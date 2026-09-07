"""Mixed content: insecure http resources on an https page, split active (high) vs passive (medium);
relative/protocol-relative URLs and non-https pages are not mixed content."""
import unittest

from auditor.mixed_content import mixed_content_findings

MIXED = """<html><head>
<script src="http://cdn.example.com/app.js"></script>
<link rel="stylesheet" href="http://cdn.example.com/a.css">
<img src="http://img.example.com/logo.png">
</head><body>
<img src="/relative.png">
<img src="//cdn.example.com/protocol-relative.png">
<script src="https://secure.example.com/ok.js"></script>
</body></html>"""

CLEAN = """<html><head>
<script src="https://cdn.example.com/app.js"></script>
<img src="/logo.png"><img src="//cdn.example.com/x.png">
</head></html>"""


class MixedContentTest(unittest.TestCase):
    def test_active_and_passive_flagged_on_https(self):
        items = mixed_content_findings([("https://site.test/", MIXED)])
        by_conf = {i["confidence"] for i in items}
        self.assertEqual(by_conf, {"high", "medium"})
        high = next(i for i in items if i["confidence"] == "high")
        # script + stylesheet are both active -> counted together
        self.assertIn("2 script/style", high["evidence"])
        med = next(i for i in items if i["confidence"] == "medium")
        self.assertIn("1 image/media", med["evidence"])

    def test_relative_and_protocol_relative_are_not_mixed(self):
        # CLEAN's only resources are https, root-relative, and protocol-relative - none are http.
        self.assertEqual(mixed_content_findings([("https://site.test/", CLEAN)]), [])

    def test_http_page_is_not_mixed_content(self):
        # An http page loading http resources is insecure overall, not "mixed" - out of scope here.
        self.assertEqual(mixed_content_findings([("http://site.test/", MIXED)]), [])


if __name__ == "__main__":
    unittest.main()
