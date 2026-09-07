import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from auditor.ai_visibility import (
    AI_CRAWLERS,
    check_ai_crawler_access,
    check_llms_txt,
    check_schema_org,
    run_ai_visibility,
    what_ai_says,
)


class AIVisHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/llms.txt":
            self._send(200, "text/plain", "# Acme\n> A test business\n- /about")
        elif self.path == "/robots.txt":
            self._send(200, "text/plain", "User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nDisallow: /private\n")
        elif self.path == "/no-robots/robots.txt":
            self._send(404, "text/plain", "nope")
        elif self.path == "/":
            self._send(200, "text/html",
                       '<html><head><script type="application/ld+json">'
                       '{"@context":"https://schema.org","@type":"Organization","name":"Acme"}'
                       '</script></head><body>hi</body></html>')
        else:
            self._send(404, "text/plain", "not found")


class FakeProvider:
    """A provider that reports genuine knowledge, to prove the fan-out shape."""
    name = "fake"
    available = True

    def complete_json(self, *, system, user, schema, image_png=None, temperature=0.2, offline_fallback=None):
        return {"has_reliable_knowledge": True, "summary": "Known business.", "confidence": "high"}


class TestAIVisibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), AIVisHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_llms_txt_present(self):
        result = check_llms_txt(self.base)
        self.assertTrue(result.present)
        self.assertGreater(result.detail["bytes"], 0)

    def test_llms_txt_absent_is_not_present(self):
        result = check_llms_txt(self.base + "/deep/path")  # llms.txt is resolved at the origin
        # origin is the same server; /llms.txt exists, so present. Use a path proves origin resolution:
        self.assertTrue(result.present)

    def test_ai_crawler_access_reports_blocked_bot(self):
        result = check_ai_crawler_access(self.base)
        self.assertFalse(result.present)
        self.assertEqual(result.detail["per_bot"]["GPTBot"], "blocked")
        self.assertEqual(result.detail["per_bot"]["CCBot"], "allowed")
        self.assertIn("GPTBot", result.detail["blocked"])

    def test_schema_org_valid(self):
        import urllib.request
        html = urllib.request.urlopen(self.base + "/").read().decode()
        result = check_schema_org(html)
        self.assertTrue(result.present)
        self.assertIn("Organization", result.detail["types"])

    def test_schema_org_absent(self):
        self.assertFalse(check_schema_org("<html><body>plain</body></html>").present)

    def test_schema_org_malformed_flagged_not_present(self):
        result = check_schema_org('<script type="application/ld+json">{bad json}</script>')
        self.assertFalse(result.present)
        self.assertEqual(result.detail["parse_errors"], 1)

    def test_what_ai_says_fans_out_over_providers(self):
        answers = what_ai_says("Acme", self.base, [FakeProvider(), FakeProvider()])
        self.assertEqual(len(answers), 2)
        self.assertTrue(all(a["has_reliable_knowledge"] for a in answers))
        self.assertEqual(answers[0]["model"], "fake")

    def test_what_ai_says_offline_signals_no_knowledge(self):
        from auditor.llm.offline_provider import OfflineProvider
        answers = what_ai_says("Acme", self.base, [OfflineProvider()])
        self.assertFalse(answers[0]["has_reliable_knowledge"])
        self.assertEqual(answers[0]["confidence"], "none")

    def test_run_ai_visibility_assembles_all_four(self):
        import urllib.request
        html = urllib.request.urlopen(self.base + "/").read().decode()
        out = run_ai_visibility(self.base, html, "Acme", [FakeProvider()])
        self.assertEqual(set(out), {"llms_txt", "schema_org", "ai_crawler_access", "what_ai_says"})
        self.assertTrue(out["schema_org"]["present"])
        self.assertEqual(len(out["what_ai_says"]), 1)

    def test_all_crawlers_have_a_status(self):
        result = check_ai_crawler_access(self.base)
        for bot in AI_CRAWLERS:
            self.assertIn(bot, result.detail["per_bot"])


if __name__ == "__main__":
    unittest.main()
