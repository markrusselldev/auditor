"""Revenue-path submission verification: forms are filled and submitted in a real browser to
confirm the submit truly fires to a reachable endpoint - without ever delivering a submission or
firing the site's analytics."""
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from auditor.revenue_verify import verify_revenue_forms

# Six forms in document order. Only browser POSTs would be a real (unwanted) delivery; the
# reachability probe is a server-side GET, which is expected.
PAGE = """<!doctype html><html><body>
<form id="js-live"><input name="email" type="email"><button type="submit">send</button></form>
<form id="js-dead"><input name="email" type="email"><button type="submit">send</button></form>
<form id="native-dead" method="post" action="/native-dead">
  <input name="email" type="email"><button type="submit">send</button></form>
<form id="dead-button" action="#">
  <input name="email" type="email"><button type="submit">send</button></form>
<form id="native-ok" method="post" action="/native-ok">
  <input name="email" type="email"><button type="submit">send</button></form>
<form id="search"><input name="q" type="text"><button type="submit">go</button></form>
<script>
  const post = (id, url) => document.getElementById(id).addEventListener('submit', (e) => {
    e.preventDefault(); fetch(url, {method:'POST', body:'email=x'});
  });
  post('js-live', '/live-endpoint');
  post('js-dead', '/dead-endpoint');
  window.addEventListener('pagehide', () => navigator.sendBeacon('/beacon-unload', 'x'));
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    received: list = []

    def _send(self, code):
        self.send_response(code)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        Handler.received.append(("GET", self.path))
        if self.path == "/" or self.path.startswith("/?"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path in ("/dead-endpoint", "/native-dead"):
            self._send(404)
        else:  # /live-endpoint, /native-ok reachable
            self._send(200)

    def do_POST(self):
        ln = int(self.headers.get("Content-Length") or 0)
        if ln:
            self.rfile.read(ln)
        Handler.received.append(("POST", self.path))
        self._send(200)

    def log_message(self, *a):
        pass


class RevenueVerifyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Handler.received = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/"
        Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.findings = verify_revenue_forms([cls.base], own_site=True)
        cls.by_type = {}
        for f in cls.findings:
            cls.by_type.setdefault(f["issue_type"], []).append(f)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_dead_js_endpoint_flagged(self):
        dead = self.by_type.get("revenue_submit_dead_endpoint", [])
        urls = {f["failed_url"] for f in dead}
        self.assertTrue(any(u.endswith("/dead-endpoint") for u in urls), self.findings)

    def test_dead_native_action_flagged(self):
        dead = self.by_type.get("revenue_submit_dead_endpoint", [])
        urls = {f["failed_url"] for f in dead}
        self.assertTrue(any(u.endswith("/native-dead") for u in urls), self.findings)

    def test_dead_button_no_request_flagged(self):
        self.assertEqual(len(self.by_type.get("revenue_submit_no_request", [])), 1, self.findings)

    def test_healthy_forms_not_flagged(self):
        # js-live and native-ok are reachable; search is not a candidate. Exactly the 3 broken ones.
        self.assertEqual(len(self.findings), 3, self.findings)

    def test_no_submission_reached_an_endpoint(self):
        # The real safety guarantee: no form submission is ever delivered. A reachability probe is
        # a GET; a delivered submission would be a POST to a form endpoint.
        form_endpoints = {"/live-endpoint", "/dead-endpoint", "/native-ok", "/native-dead"}
        delivered = [p for method, p in Handler.received if method == "POST" and p in form_endpoints]
        self.assertEqual(delivered, [], f"a form submission was delivered: {delivered}")

    def test_form_submits_never_unloaded_the_page(self):
        # The fixture beacons on pagehide. Submitting five forms must not unload the page (that is
        # what would fire the owner's analytics an extra event) - the only unload is teardown, so
        # the beacon fires at most once. More than once means a submit navigated.
        beacons = [p for _m, p in Handler.received if p == "/beacon-unload"]
        self.assertLessEqual(len(beacons), 1, f"a submit unloaded the page: {len(beacons)} beacons")

    def test_consent_gate_refuses_without_own_site(self):
        self.assertEqual(verify_revenue_forms([self.base], own_site=False), [])


if __name__ == "__main__":
    unittest.main()
