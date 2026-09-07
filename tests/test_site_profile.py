import unittest

from auditor.site_profile import build_site_profile, classify_load, detect_stack


class TestSiteProfile(unittest.TestCase):
    def test_wordpress_from_html_path(self):
        html = '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
        self.assertEqual(detect_stack(html)["cms"], "WordPress")

    def test_cms_from_generator_meta(self):
        html = '<meta name="generator" content="Drupal 10 (https://www.drupal.org)">'
        stack = detect_stack(html)
        self.assertEqual(stack["cms"], "Drupal")
        self.assertIn("Drupal", stack["generator"])

    def test_shopify_and_frameworks(self):
        html = '<script src="https://cdn.shopify.com/s/app.js"></script><div id="__NEXT_DATA__"></div>'
        stack = detect_stack(html)
        self.assertEqual(stack["cms"], "Shopify")
        self.assertIn("Next.js", stack["frameworks"])

    def test_cdn_and_server_from_headers(self):
        stack = detect_stack("<html></html>", {"CF-Ray": "abc", "Server": "cloudflare", "X-Powered-By": "PHP/8.2"})
        self.assertEqual(stack["cdn"], "Cloudflare")
        self.assertEqual(stack["powered_by"], "PHP/8.2")

    def test_unknown_site_is_all_empty(self):
        stack = detect_stack("<html><body>plain</body></html>", {})
        self.assertEqual(stack["cms"], "")
        self.assertEqual(stack["frameworks"], [])
        self.assertEqual(stack["cdn"], "")

    def test_load_classification(self):
        self.assertEqual(classify_load({"load": 1800, "ttfb": 200, "dcl": 900})["label"], "fast")
        self.assertEqual(classify_load({"load": 3500})["label"], "moderate")
        self.assertEqual(classify_load({"load": 7000})["label"], "slow")
        self.assertEqual(classify_load({}), {})
        self.assertEqual(classify_load({"load": 0, "dcl": 0, "duration": 0}), {})

    def test_build_site_profile_shape(self):
        profile = build_site_profile("/wp-content/", {"server": "nginx"}, {"load": 2000})
        self.assertEqual(profile["tech"]["cms"], "WordPress")
        self.assertEqual(profile["tech"]["server"], "nginx")
        self.assertEqual(profile["load"]["label"], "fast")


if __name__ == "__main__":
    unittest.main()
