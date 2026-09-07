import csv
import io
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from auditor.scanner import (
    FetchResult,
    classify_target,
    discover_page,
    is_dangerous_url,
    is_suspicious_destination,
    normalize_url,
    is_valid_mailto,
    scan_csv,
    scan_organization,
    severity_for,
)


FIXTURES = Path(__file__).parent / "fixtures"


class FixtureHandler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        type(self).requests.append(self.path)
        routes = {
            "/": (200, (FIXTURES / "crawl-home.html").read_text()),
            "/priority": (200, '<a href="/depth-two">More information</a><a href="/broken-donate">Donate now</a>'),
            "/ordinary": (200, '<a href="/contact">Contact</a>'),
            "/overflow": (200, "Programs"),
            "/depth-two": (200, "Must not be crawled"),
            "/contact": (200, "Contact page"),
            "/broken-donate": (404, "Missing"),
        }
        status, body = routes.get(self.path, (404, "Missing"))
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, _format, *args):
        pass


class ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.homepage = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        FixtureHandler.requests = []


class DiscoveryTests(unittest.TestCase):
    def test_discovers_anchor_form_button_iframe_and_metadata(self):
        html = (FIXTURES / "discovery.html").read_text()
        targets, _ = discover_page(html, "https://nonprofit.org/")
        values = {(target.kind, target.category, target.url, target.invalid_reason) for target in targets}
        self.assertIn(("anchor", "donation", "https://nonprofit.org/give", ""), values)
        self.assertIn(("anchor", "ticket", "https://nonprofit.org/tickets", ""), values)
        self.assertIn(("iframe", "ticket", "https://tickets.vendor.invalid/widget", ""), values)
        self.assertIn(("form", "membership", "https://nonprofit.org/membership", ""), values)
        self.assertIn(("button", "registration", "https://nonprofit.org/rsvp", ""), values)
        self.assertIn(("button", "contact", "https://nonprofit.org/contact", ""), values)
        self.assertTrue(any(target.invalid_reason == "missing form action" for target in targets))

    def test_categories(self):
        cases = {
            "Donate now": "donation",
            "Box Office": "ticket",
            "Events calendar": "event",
            "Contact us": "contact",
            "Renew membership": "membership",
            "RSVP": "registration",
        }
        for value, category in cases.items():
            with self.subTest(value=value):
                self.assertEqual(classify_target(value), category)

    def test_normalization_filtering_and_deduplication(self):
        self.assertEqual(
            normalize_url("HTTPS://Example.ORG:443/a//b?z=2&a=1#top"),
            "https://example.org/a/b?a=1&z=2",
        )
        html = '<a href="/donate#one">Donate</a><a href="/donate#two">Give</a>'
        targets, _ = discover_page(html, "https://example.org/")
        self.assertEqual([target.url for target in targets], ["https://example.org/donate"])

    def test_unicode_url_is_encoded_without_double_encoding(self):
        self.assertEqual(
            normalize_url("https://café.example/give/☕/already%20encoded?q=☕&next=%2Fok"),
            "https://xn--caf-dma.example/give/%E2%98%95/already%20encoded?next=%2Fok&q=%E2%98%95",
        )

    def test_excludes_dangerous_urls(self):
        for url in (
            "https://example.org/login", "https://example.org/wp-admin/",
            "https://example.org/cart?action=remove", "https://example.org/search?q=donate",
        ):
            with self.subTest(url=url):
                self.assertTrue(is_dangerous_url(url))

    def test_suspicious_test_and_staging_destinations(self):
        for url in (
            "https://staging.nonprofit.org/donate", "https://vendor.org/sandbox/pay",
            "https://example.com/donate", "http://localhost:8000/give",
        ):
            with self.subTest(url=url):
                self.assertTrue(is_suspicious_destination(url))
        self.assertFalse(is_suspicious_destination("https://www.paypal.com/donate"))

    def test_severity_tracks_revenue_impact(self):
        self.assertEqual(severity_for("donation", "broken_revenue_target"), "critical")
        self.assertEqual(severity_for("ticket", "broken_revenue_target"), "critical")
        self.assertEqual(severity_for("registration", "broken_revenue_target"), "high")
        self.assertEqual(severity_for("donation", "suspicious_destination"), "medium")

    def test_valid_mailto_contact_form_is_intentional(self):
        html = (
            '<form action="mailto:boxoffice@nonprofit.org"><label>Contact us</label></form>'
            '<a href="mailto:info@nonprofit.org">Contact Us</a>'
        )
        targets, _ = discover_page(html, "https://nonprofit.org/")
        self.assertEqual(targets, [])
        self.assertTrue(is_valid_mailto("mailto:boxoffice@nonprofit.org?subject=Tickets"))

    def test_invalid_revenue_form_actions_are_reported(self):
        actions = ("", "mailto:not-an-address", "javascript:void(0)", "#", "about:blank")
        for action in actions:
            with self.subTest(action=action):
                html = f'<form action="{action}"><label>Contact us</label></form>'
                targets, _ = discover_page(html, "https://nonprofit.org/")
                self.assertEqual(len(targets), 1)
                self.assertTrue(targets[0].invalid_reason)

    def test_mailto_is_only_exempt_for_contact_forms(self):
        html = '<form action="mailto:gifts@nonprofit.org"><label>Donate now</label></form>'
        targets, _ = discover_page(html, "https://nonprofit.org/")
        self.assertEqual(targets[0].invalid_reason, "invalid action URL")


class CrawlTests(ServerTestCase):
    def test_crawl_is_shallow_prioritized_same_site_and_capped(self):
        _findings, summary = scan_organization("Fixture", self.homepage, 2, max_pages=2)
        self.assertEqual(summary.pages_scanned, 2)
        self.assertIn("/priority", FixtureHandler.requests)
        self.assertNotIn("/ordinary", FixtureHandler.requests)
        self.assertNotIn("/depth-two", FixtureHandler.requests)
        self.assertFalse(any("external.invalid" in path for path in FixtureHandler.requests))
        self.assertNotIn("/login", FixtureHandler.requests)

    def test_unicode_discovered_url_does_not_abort_scan(self):
        with patch("auditor.scanner._fetch_confirming_timeout") as fetch:
            fetch.side_effect = [
                FetchResult(
                    "https://nonprofit.org/", "https://nonprofit.org/", 200, "ok",
                    content_type="text/html", body='<a href="/donate/☕">Donate</a>',
                ),
                FetchResult(
                    "https://nonprofit.org/donate/%E2%98%95", "https://nonprofit.org/donate/%E2%98%95", 200, "ok",
                ),
            ]
            findings, summary = scan_organization("Unicode", "https://nonprofit.org/", 1, 1)
        self.assertEqual(findings, [])
        self.assertEqual(summary.revenue_targets_checked, 1)
        self.assertEqual(fetch.call_args_list[1].args[0], "https://nonprofit.org/donate/%E2%98%95")


class OutputTests(ServerTestCase):
    def test_findings_only_and_summary_outputs(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "input.csv"
            input_path.write_text(f"organization,url\nFixture,{self.homepage}\n")
            findings, summaries = scan_csv(input_path, root / "output", timeout=2, max_pages=3)
            self.assertEqual(len(summaries), 1)
            self.assertTrue(findings)
            self.assertTrue(all(finding.finding_type != "ok" for finding in findings))
            with (root / "output" / "findings.csv").open(newline="") as handle:
                finding_rows = list(csv.DictReader(handle))
            with (root / "output" / "scan-summary.csv").open(newline="") as handle:
                summary_rows = list(csv.DictReader(handle))
            self.assertEqual(len(finding_rows), len(findings))
            self.assertEqual(finding_rows[0]["finding_type"], "broken_revenue_target")
            self.assertEqual(finding_rows[0]["severity"], "critical")
            self.assertEqual(len(summary_rows), 1)
            self.assertEqual(int(summary_rows[0]["pages_scanned"]), 3)
            self.assertEqual(int(summary_rows[0]["actionable_findings"]), len(findings))
            self.assertEqual(summary_rows[0]["scan_outcome"], "findings")

    def test_completed_organization_is_saved_before_later_interruption(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "input.csv"
            input_path.write_text(
                f"organization,url\nFirst,{self.homepage}\nSecond,{self.homepage}\n"
            )
            real_scan = scan_organization

            def interrupt_second(organization, homepage, timeout, max_pages):
                if organization == "Second":
                    raise KeyboardInterrupt
                return real_scan(organization, homepage, timeout, max_pages)

            output = io.StringIO()
            with patch("auditor.scanner.scan_organization", side_effect=interrupt_second):
                with self.assertRaises(KeyboardInterrupt), redirect_stdout(output):
                    scan_csv(input_path, root / "output", timeout=2, max_pages=1)
            with (root / "output" / "scan-summary.csv").open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["organization"] for row in rows], ["First"])
            self.assertIn("[1/2] First - 1 pages", output.getvalue())

    def test_resume_preserves_completed_rows_and_scans_only_remaining(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "input.csv"
            input_path.write_text(f"organization,url\nFirst,{self.homepage}\nSecond,{self.homepage}\n")
            output_dir = root / "output"
            output_dir.mkdir()
            (output_dir / "scan-summary.csv").write_text(
                "organization,homepage,pages_scanned,revenue_targets_checked,actionable_findings,critical_findings,high_findings,scan_outcome\n"
                f"First,{self.homepage},1,0,0,0,0,ok\n"
            )
            (output_dir / "findings.csv").write_text(
                "organization,homepage,finding_type,category,severity,source_page,link_text_or_control,tested_url,final_url,status_code,evidence,verification,elapsed_ms\n"
            )
            with patch("auditor.scanner.scan_organization", wraps=scan_organization) as scan:
                findings, summaries = scan_csv(input_path, output_dir, 2, 1, resume=True)
            self.assertEqual([call.args[0] for call in scan.call_args_list], ["Second"])
            self.assertEqual([summary.organization for summary in summaries], ["First", "Second"])
            self.assertEqual(len({summary.organization for summary in summaries}), 2)
            self.assertEqual(len(findings), len({tuple(vars(item).values()) for item in findings}))


class TimeoutHandler(BaseHTTPRequestHandler):
    requests: dict[str, int] = {}

    def do_GET(self):
        count = type(self).requests.get(self.path, 0) + 1
        type(self).requests[self.path] = count
        if self.path == "/eventual" and count == 1:
            time.sleep(0.15)
        elif self.path == "/repeated":
            time.sleep(10.2)
        if self.path == "/":
            body = '<a href="/eventual">Donate now</a>'
        elif self.path == "/home-with-repeated":
            body = '<a href="/repeated">Donate now</a>'
        else:
            body = "OK"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode())
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, _format, *args):
        pass


class TimeoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), TimeoutHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        TimeoutHandler.requests = {}

    def test_revenue_target_first_timeout_then_success_is_not_reported(self):
        findings, summary = scan_organization("Eventual", self.base + "/", 0.05, max_pages=1)
        self.assertEqual(findings, [])
        self.assertEqual(summary.revenue_targets_checked, 1)
        self.assertEqual(TimeoutHandler.requests["/eventual"], 2)

    def test_repeated_revenue_target_timeout_records_both_attempts(self):
        homepage = self.base + '/home-with-repeated'
        findings, _summary = scan_organization("Repeated", homepage, 0.05, max_pages=1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "revenue_target_timeout")
        self.assertIn("attempt 1: timeout=0.05s, outcome=timeout", findings[0].verification)
        self.assertIn("attempt 2: timeout=10s, outcome=timeout", findings[0].verification)
        self.assertEqual(TimeoutHandler.requests["/repeated"], 2)


if __name__ == "__main__":
    unittest.main()
