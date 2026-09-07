import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from auditor.vision_capture import capture_for_vision

GATED = """<!doctype html><html><head><meta charset=utf-8><title>Gated</title></head>
<body>
<h1>Grow California natives with local, water-wise methods</h1>
<p>Real homepage content that should be readable once the gate is gone.</p>
<div id="gate" style="position:fixed;inset:0;background:#111;color:#fff;z-index:9999;
     display:flex;align-items:center;justify-content:center;flex-direction:column">
  <p>You must confirm your age to enter.</p>
  <button onclick="document.getElementById('gate').remove()">I am over 21 - Enter Site</button>
</div>
</body></html>"""

CLEAN = """<!doctype html><html><head><meta charset=utf-8><title>Clean</title></head>
<body><h1>Welcome</h1><a href="/next">Continue reading our blog</a>
<button>Get started</button></body></html>"""

# A form with a real JS submit handler wired up.
JS_FORM = """<!doctype html><html><body>
<form><input type="email" name="email"><button type="submit">Send</button></form>
<script>document.querySelector('form').addEventListener('submit', function (e) { e.preventDefault(); });</script>
</body></html>"""

# The same form with NO handler: submitting it would just reload and lose the data.
NO_HANDLER_FORM = """<!doctype html><html><body>
<form><input type="email" name="email"><button type="submit">Send</button></form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = {"/gated": GATED, "/clean": CLEAN, "/js-form": JS_FORM, "/no-handler": NO_HANDLER_FORM}.get(self.path, "<h1>ok</h1>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


class TestVisionCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_dismisses_age_gate_and_reveals_page(self):
        png, info = capture_for_vision(self.base + "/gated", timeout=20)
        self.assertIsNotNone(png)
        self.assertFalse(info["overlay_remaining"])

    def test_reports_the_gate_for_a_finding(self):
        _png, info = capture_for_vision(self.base + "/gated", timeout=20)
        self.assertTrue(info["gate"]["present"])
        self.assertEqual(info["gate"]["type"], "age gate")

    def test_verifies_js_submit_handler_present_vs_absent(self):
        _png, info = capture_for_vision(
            self.base + "/clean", timeout=20,
            form_check_pages=[self.base + "/js-form", self.base + "/no-handler"],
        )
        handlers = info.get("form_handlers", {})
        self.assertEqual(handlers.get(self.base + "/js-form"), [True])
        self.assertEqual(handlers.get(self.base + "/no-handler"), [False])

    def test_clean_page_is_not_clicked(self):
        # No blocking overlay: the dismisser must not click "Continue" or "Get started" and wander off.
        png, info = capture_for_vision(self.base + "/clean", timeout=20)
        self.assertIsNotNone(png)
        self.assertEqual(info["dismissed"], 0)
        self.assertFalse(info["overlay_remaining"])


if __name__ == "__main__":
    unittest.main()
