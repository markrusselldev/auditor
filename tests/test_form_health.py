import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from auditor.form_health import (
    apply_form_handlers,
    detect_forms,
    findings_from_forms,
    js_check_pages,
)

CONTACT = """<form action="/send" method="post">
  <input type="text" name="name" required>
  <input type="email" name="email" required>
  <textarea name="message"></textarea>
  <button type="submit">Send Message</button>
</form>"""

# A GET-method form whose action 404s: the browser fetches the action with a GET on submit, so a
# 404 is a genuinely dead destination (the case a GET probe can legitimately judge).
DEAD = """<form action="/dead-endpoint" method="get">
  <input type="email" name="email"><button type="submit">Search</button>
</form>"""

# A footer newsletter form, JS-handled (empty action), that repeats on every page.
NEWSLETTER = '<form><input type="email" name="news"><button>Subscribe</button></form>'

# A GET search form: the bare action 404s, but the real submission (action?q=...) is 200. Probing the
# bare action would falsely flag it; probing with the form's own params must not (Shopify /search).
SEARCH = '<form action="/search" method="get"><input type="search" name="q"><button>Search</button></form>'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        from urllib.parse import urlsplit
        parts = urlsplit(self.path)
        if parts.path == "/send":
            code = 200
        elif parts.path == "/search":
            code = 200 if parts.query else 404  # bare /search 404s; /search?q=... is a real search
        else:
            code = 404
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"ok")


class TestFormHealth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_healthy_contact_form_reports_submit_target(self):
        forms = detect_forms([(self.base + "/contact", CONTACT + NEWSLETTER)])
        contact = next(f for f in forms if f["submit_target"].endswith("/send"))
        self.assertEqual(contact["health"], "healthy")
        self.assertTrue(contact["has_email"])
        self.assertTrue(contact["has_message"])
        self.assertTrue(contact["has_submit"])

    def test_dead_action_flagged_and_framed_as_lost_submissions(self):
        forms = detect_forms([(self.base + "/", DEAD)])
        dead = forms[0]
        self.assertEqual(dead["health"], "broken")
        self.assertEqual(dead["action_status"], 404)
        self.assertIn("form_action_dead", dead["issues"])
        findings = findings_from_forms(forms)
        self.assertEqual(len(findings), 1)
        self.assertIn("silently lost", findings[0]["evidence"])
        self.assertEqual(findings[0]["confidence"], "high")

    def test_get_search_form_probed_with_its_params_not_bare_action(self):
        # A GET search form submits to action?q=..., not the bare action. The bare /search 404s but the
        # real query is 200, so probing with the form's own field names (like a real submission) must
        # not flag it. Bare-action probing was the /search false positive.
        forms = detect_forms([(self.base + "/", SEARCH)])
        form = forms[0]
        self.assertEqual(form["action_status"], 200)          # probed with the query present
        self.assertNotIn("form_action_dead", form["issues"])
        self.assertEqual(findings_from_forms(forms), [])

    def test_same_origin_post_action_404_is_not_flagged(self):
        # A POST form whose action 404s a GET is NOT judged dead even on the site's own domain:
        # Shopify's own /contact, a form-engine token endpoint, etc. all 404 a bare GET while
        # accepting POSTs. A GET probe can only judge a GET-method form.
        post = (
            '<form action="/dead-endpoint" method="post">'
            '<input type="email" name="email"><button type="submit">Join</button></form>'
        )
        forms = detect_forms([(self.base + "/", post)])
        form = forms[0]
        self.assertEqual(form["action_status"], 404)      # we did probe it
        self.assertNotIn("form_action_dead", form["issues"])  # but a POST 404 is not "dead"
        self.assertEqual(findings_from_forms(forms), [])

    def test_third_party_post_action_404_is_not_flagged(self):
        # A POST form whose action is a hosted third-party endpoint (Mailchimp, PayPal, etc.)
        # routinely 404s a bare GET while accepting POSTs. A GET probe cannot judge it dead, so a
        # cross-site action is not flagged. localhost vs 127.0.0.1 are the same fixture server but
        # different hosts, standing in for a third-party endpoint.
        port = self.server.server_address[1]
        third_party = (
            f'<form action="http://localhost:{port}/dead-endpoint" method="post">'
            '<input type="email" name="email"><button type="submit">Join</button></form>'
        )
        forms = detect_forms([(self.base + "/", third_party)])
        form = forms[0]
        self.assertEqual(form["action_status"], 404)      # we did probe it
        self.assertNotIn("form_action_dead", form["issues"])  # but a cross-site POST 404 is not "dead"
        self.assertEqual(findings_from_forms(forms), [])

    def test_repeated_form_collapses_across_pages(self):
        pages = [(self.base + "/", NEWSLETTER), (self.base + "/about", NEWSLETTER), (self.base + "/x", NEWSLETTER)]
        forms = detect_forms(pages)
        news = [f for f in forms if any("news" in n for n in f["field_names"])][0]
        self.assertEqual(len(news["pages"]), 3)  # one record, three pages

    def test_js_handled_form_is_not_flagged_broken(self):
        forms = detect_forms([(self.base + "/", NEWSLETTER)])
        self.assertEqual(forms[0]["kind"], "same_page")
        self.assertEqual(forms[0]["issues"], [])

    def test_covers_all_supplied_pages(self):
        forms = detect_forms([(self.base + "/contact", CONTACT), (self.base + "/join", DEAD)])
        self.assertEqual(len(forms), 2)

    def test_js_handler_verified_marks_form_handled(self):
        page = self.base + "/contact"
        # A JS contact form (empty action): checkable page is listed, and a handler is confirmed.
        forms = detect_forms([(page, '<form><input type="email" name="email"><textarea name="message"></textarea><button>Send</button></form>')])
        self.assertEqual(js_check_pages(forms), [page])
        apply_form_handlers(forms, {page: [True]})
        self.assertEqual(forms[0]["kind"], "js_handled")
        self.assertEqual(findings_from_forms(forms), [])

    def test_no_js_handler_on_contact_form_is_a_finding(self):
        page = self.base + "/contact"
        forms = detect_forms([(page, '<form><input type="email" name="email"><textarea name="message"></textarea><button>Send</button></form>')])
        apply_form_handlers(forms, {page: [False]})
        self.assertEqual(forms[0]["health"], "broken")
        findings = findings_from_forms(forms)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["issue_type"], "form_no_submit_handler")
        self.assertIn("go nowhere", findings[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
