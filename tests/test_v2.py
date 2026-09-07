import asyncio
import concurrent.futures
import csv
import inspect
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlsplit

from auditor.v2 import (
    MAX_PAGES, CoverageRow, InventoryParser, OpportunityRow, OrganizationSummaryRow, PageRecord, ResultRow, _coverage_status, _detach_iframes, apply_nav_reachability_gate, browser_audit, check_homepage_links, classify_http_results, confidence_for, crawl_inventory,
    deduplicate_results, enrich_findings, migration_finding, normalize_inventory_url, rank_findings, resolve_canonical_homepage, run_audit_v2, skip_reason, suppress_origin_findings, url_kind,
)
from auditor.v2 import _fetch_asset, _run_stable_revenue_verifier, _variant_is_ok
from auditor import cli
from auditor.browser_verifier import BrowserEvidence


TINY_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108020000009077"
    "53de0000000c4944415408d763f8ffff3f0005fe02fea1f5e5460000000049454e44ae426082"
)


class V2Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow.png":
            time.sleep(3)
            self.send_response(200); self.send_header("Content-Type", "image/png"); self.end_headers()
            self.wfile.write(TINY_PNG)
            return
        if self.path == "/tiny.png":
            self.send_response(200); self.send_header("Content-Type", "image/png"); self.end_headers()
            self.wfile.write(TINY_PNG)
            return
        if self.path == "/slow-home":
            body = '<a href="/contact">Contact</a><a href="/slow-child">Slow child</a>'
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(body.encode())
            return
        if self.path == "/slow-child":
            time.sleep(1.5)
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(b"slow child body")
            return
        if self.path == "/redir-variant/":
            # Slash variant that 301s to a working page, as a bare host redirecting to www does.
            self.send_response(301); self.send_header("Location", "/special-events/"); self.end_headers()
            return
        routes = {
            "/": (200, "text/html", '''<a href="/contact">Contact</a><a href="/shop">Shop</a>
              <a href="/page/2">Next</a><a href="/?utm_source=x">Tracked</a>
              <img src="/missing.png"><link rel="stylesheet" href="/site.css">'''),
            "/contact": (200, "text/html", "Email or call for price and availability"),
            "/shop": (200, "text/html", '<a href="/product/one">One</a><a href="/product/two">Two</a>'),
            "/product/one": (200, "text/html", '<a href="/cart">Cart</a>'),
            "/cart": (200, "text/html", '<a href="/checkout">Checkout</a>'),
            "/checkout": (200, "text/html", "Checkout"),
            "/site.css": (200, "text/css", "body{background:url('/missing-bg.png')}"),
            "/contact-mobile-hidden": (200, "text/html", '''<meta name="viewport" content="width=device-width"><style>@media(max-width:500px){#primary{display:none}}</style><a id="primary" href="/contact">Contact Us</a>'''),
            "/donate-mobile-overlay": (200, "text/html", '''<meta name="viewport" content="width=device-width"><a href="/donate">Donate</a><div role="dialog" style="position:fixed;inset:0;background:white">Blocking modal</div>'''),
            "/shop-mobile-overflow": (200, "text/html", '''<meta name="viewport" content="width=device-width"><a href="/shop">Shop</a><div style="width:900px">wide visitor content</div>'''),
            # Overflows at BOTH desktop (1440) and mobile (390): NOT mobile-only, must be suppressed.
            "/overflow-both": (200, "text/html", '''<meta name="viewport" content="width=device-width"><a href="/shop">Shop</a><div style="width:2000px">extremely wide content overflowing every viewport</div>'''),
            # Donate is a discoverable control at desktop; a media query hides the nav at mobile and the
            # hamburger is inert (no JS), so a phone visitor cannot reach Donate: mobile-only unreachable.
            "/broken-hamburger": (200, "text/html", '''<meta name="viewport" content="width=device-width">
              <style>@media(max-width:500px){#mainnav{display:none}}</style>
              <button aria-label="Open menu" class="hamburger">Menu</button>
              <nav id="mainnav"><a href="/donate">Donate</a></nav>'''),
            # <picture> whose mobile source 404s only at the phone breakpoint; desktop uses the 200 img.
            "/mobile-broken-asset": (200, "text/html", '''<meta name="viewport" content="width=device-width">
              <picture><source media="(max-width:500px)" srcset="/missing-mobile.png">
              <img src="/tiny.png" width="200" height="150" alt="hero"></picture>'''),
            "/forms": (200, "text/html", '''<script>let a=document.createElement('a');a.href='/js-only';a.textContent='JS only';document.body.append(a)</script>
              <form><input name="email"><button type="submit">Send Message</button></form>
              <form><div>Broken application</div></form><iframe src="http://127.0.0.1:1/widget"></iframe>'''),
            "/soft": (200, "text/html", "Page not found. Return home."),
            "/rebuilding": (200, "text/html", "We are rebuilding our website."),
            "/parked": (200, "text/html", "This domain is for sale. Related commercial searches."),
            "/clean": (200, "text/html", "Welcome. Ordinary public information."),
            "/image-loading": (200, "text/html", '<img src="/slow.png" width="200" height="150">'),
            "/image-broken": (200, "text/html", '<img src="/broken.png" width="200" height="150">'),
            "/iframes": (200, "text/html", '<a href="/contact">Contact</a><iframe src="/clean"></iframe><iframe src="/shop"></iframe>'),
            # Trailing-slash variant: the slashed form serves 200; the crawl-normalized bare form 404s.
            "/special-events/": (200, "text/html", "Special events"),
        }
        status, content_type, body = routes.get(self.path, (404, "text/html", "Page not found"))
        self.send_response(status); self.send_header("Content-Type", content_type); self.end_headers(); self.wfile.write(body.encode())

    def log_message(self, *_args): pass


class V2PolicyTests(unittest.TestCase):
    def test_normalization_and_catalog_limits(self):
        self.assertEqual(normalize_inventory_url("https://EXAMPLE.org/shop/?utm_source=x#top"), "https://example.org/shop")
        # www and the bare host canonicalize to one site so internal links are not skipped.
        self.assertEqual(normalize_inventory_url("https://www.example.org/about"), "https://example.org/about")
        self.assertEqual(skip_reason("https://www.example.org/about", "https://example.org", {"listing": "", "product": "", "cart": "", "checkout": "", "calendar": ""}), "")
        budgets = {"listing": "https://example.org/shop", "product": "https://example.org/product/one", "cart": "", "checkout": "", "calendar": ""}
        self.assertEqual(skip_reason("https://example.org/store", "https://example.org", budgets), "organization_listing_limit")
        self.assertEqual(skip_reason("https://example.org/product/two", "https://example.org", budgets), "organization_product_limit")
        self.assertEqual(skip_reason("https://example.org/shop?page=2", "https://example.org", budgets), "pagination_sort_filter_search_or_calendar_variant")
        self.assertEqual(url_kind("https://example.org/checkout"), "checkout")

    def test_normalize_rejects_prose_href_with_spaces_or_control_chars(self):
        # A headline linked as an href (a real site linked a full sentence). urllib raises
        # InvalidURL on the space, which aborted the whole org's scan; reject it before it is enqueued.
        prose = "https://example.org/City explores future of the theater as event space"
        self.assertEqual(normalize_inventory_url(prose), "")
        self.assertEqual(normalize_inventory_url("https://x.test/two words"), "")
        self.assertEqual(skip_reason(prose, "https://example.org", {"listing": "", "product": "", "cart": "", "checkout": "", "calendar": ""}), "unsupported_or_invalid_url")
        # A well-formed neighbor on the same page is unaffected.
        self.assertEqual(normalize_inventory_url("https://example.org/tickets"), "https://example.org/tickets")

    def test_malformed_href_is_skipped_without_aborting_the_page(self):
        # One bad href on the homepage must not abort the scan: the good dead link is still reported
        # and the prose href is silently dropped (never fetched), so the org scans to completion.
        home = PageRecord("https://one.test/", "", 0, "homepage", 200, "https://one.test/", "https://one.test/", "text/html")
        parser = InventoryParser("https://one.test/")
        parser.feed('<a href="/gone">Support Us</a>'
                    '<a href="City explores future of the theater as arts orgs are squeezed">Headline</a>')
        home.parser = parser
        def fake_fetch(url, timeout=15):
            self.assertNotIn(" ", url)  # a space-bearing URL must never reach the fetcher
            return (404 if url.endswith("/gone") else 200), url, "text/html"
        with patch("auditor.v2._fetch_asset", side_effect=fake_fetch):
            rows = check_homepage_links("One", [home])
        self.assertEqual([r.failed_url for r in rows], ["https://one.test/gone"])

    def test_fetch_asset_never_propagates_a_malformed_url(self):
        # Defense in depth: even if a malformed URL reaches the fetcher, it reads as unreachable
        # (empty status) rather than raising InvalidURL out of the fast-audit and failing the org.
        status, final, _detail = _fetch_asset("https://x.test/a b c", timeout=1)
        self.assertEqual(status, "")
        self.assertEqual(final, "https://x.test/a b c")

    def test_parser_finds_links_images_and_inline_backgrounds(self):
        parser = InventoryParser("https://example.org/")
        parser.feed('<a href="/contact">Contact</a><img src="/bad.png"><img src="data:,"><img src="data:image/svg+xml,%3Csvg/%3E"><div style="background:url(/bg.png)"></div>')
        self.assertIn(("https://example.org/contact", ""), parser.links)
        self.assertIn(("https://example.org/bad.png", "image"), parser.assets)
        self.assertIn(("https://example.org/bg.png", "css_background_image"), parser.assets)
        self.assertFalse(any(url.startswith("data:") for url, _kind in parser.assets))

    def test_duplicate_findings_merge_on_only_the_declared_identity(self):
        first = ResultRow("One", "broken_image", "https://one.test", "https://one.test/a.png", 404, "first")
        duplicate = ResultRow("One", "broken_image", "https://one.test", "https://one.test/a.png", 404, "second")
        distinct = ResultRow("One", "broken_image", "https://one.test/other", "https://one.test/a.png", 404, "third")
        merged = deduplicate_results([first, duplicate, distinct])
        self.assertEqual(len(merged), 2)
        self.assertIn("first | second", merged[0].evidence)

    def test_http_failures_are_high_confidence_regardless_of_revenue_path(self):
        # A verified failure is high-confidence whether or not it sits on a revenue path.
        pages = [
            PageRecord("https://one.test/donate", "https://one.test", 1, "navigation", status_code=404, final_url="https://one.test/donate"),
            PageRecord("https://one.test/about", "https://one.test", 1, "navigation", status_code=404, final_url="https://one.test/about"),
            PageRecord("https://one.test/contact", "https://one.test", 1, "navigation", error="connection reset"),
            PageRecord("https://one.test/blog", "https://one.test", 1, "navigation", error="connection reset"),
        ]
        rows, _opportunities = classify_http_results("One", pages)
        enrich_findings(rows)
        self.assertTrue(all(row.confidence == "high" for row in rows))
        self.assertEqual({row.failed_url for row in rows if row.revenue_relevant}, {"https://one.test/donate", "https://one.test/contact"})
        self.assertEqual({row.failed_url for row in rows if not row.revenue_relevant}, {"https://one.test/about", "https://one.test/blog"})

    def test_check_homepage_links_flags_uncrawled_dead_link_only(self):
        home = PageRecord("https://one.test/", "", 0, "homepage", 200, "https://one.test/", "https://one.test/", "text/html")
        parser = InventoryParser("https://one.test/")
        # /contact is crawled; /gone is a dead link the crawl never fetched; /doc.pdf is an asset.
        parser.feed('<a href="/contact">Contact</a><a href="/gone">Support Us</a>'
                    '<a href="/doc.pdf">Doc</a><a href="https://other.test/x">External</a>')
        home.parser = parser
        contact = PageRecord("https://one.test/contact", "https://one.test/", 1, "nav", 200, "https://one.test/contact", "https://one.test/contact", "text/html")
        def fake_fetch(url, timeout=15):
            return (404 if url.endswith("/gone") else 200), url, "text/html"
        with patch("auditor.v2._fetch_asset", side_effect=fake_fetch):
            rows = check_homepage_links("One", [home, contact])
        enrich_findings(rows)
        self.assertEqual([r.failed_url for r in rows], ["https://one.test/gone"])
        self.assertEqual(rows[0].issue_type, "dead_link")
        self.assertEqual(rows[0].confidence, "high")

    def test_confidence_for_maps_verification_strength(self):
        self.assertEqual(confidence_for("page_http_failure"), "high")
        self.assertEqual(confidence_for("broken_image"), "high")
        self.assertEqual(confidence_for("ssl_certificate_failure"), "high")
        self.assertEqual(confidence_for("visible_site_failure"), "medium")
        self.assertEqual(confidence_for("unreachable_image"), "medium")
        # A mobile-only overflow or asset failure verified against a clean desktop baseline is
        # high-confidence; the heuristic navigation/tap-target mobile issues stay medium.
        self.assertEqual(confidence_for("mobile_horizontal_overflow"), "high")
        self.assertEqual(confidence_for("mobile_broken_image"), "high")
        self.assertEqual(confidence_for("mobile_broken_css"), "high")
        self.assertEqual(confidence_for("mobile_nav_unopenable"), "medium")
        self.assertEqual(confidence_for("mobile_primary_action_unusable"), "medium")
        self.assertEqual(confidence_for("mobile_tap_target_too_small"), "medium")
        self.assertEqual(confidence_for("interface_usable_submission_not_tested"), "low")

    def test_ssl_error_is_labeled_and_high_confidence(self):
        page = PageRecord("https://one.test", "https://one.test", 0, "homepage", error="SSLCertVerificationError: CERTIFICATE_VERIFY_FAILED")
        rows, _opportunities = classify_http_results("One", [page])
        enrich_findings(rows)
        self.assertEqual([row.issue_type for row in rows], ["ssl_certificate_failure"])
        self.assertEqual(rows[0].confidence, "high")

    def test_rank_findings_orders_high_then_revenue_first(self):
        low = ResultRow("One", "interface_usable_submission_not_tested", "https://one.test", "https://one.test/a", "", "e", confidence="low")
        high_nonrev = ResultRow("One", "broken_image", "https://one.test", "https://one.test/z.png", 404, "e", confidence="high")
        high_rev = ResultRow("One", "page_http_failure", "https://one.test", "https://one.test/donate", 404, "e", confidence="high", revenue_relevant=True)
        medium = ResultRow("One", "visible_site_failure", "https://one.test", "https://one.test/p", 200, "e", confidence="medium")
        ranked = rank_findings([low, high_nonrev, high_rev, medium])
        self.assertEqual(
            [row.issue_type for row in ranked],
            ["page_http_failure", "broken_image", "visible_site_failure", "interface_usable_submission_not_tested"],
        )

    def test_rank_findings_first_party_before_third_party(self):
        first_party = ResultRow("One", "broken_image", "https://one.test", "https://one.test/a.png", 404, "e", confidence="high")
        third = ResultRow("One", "broken_image", "https://one.test", "https://cdn.other/b.png", 404, "e", confidence="high", third_party=True)
        self.assertEqual(
            [row.failed_url for row in rank_findings([third, first_party])],
            ["https://one.test/a.png", "https://cdn.other/b.png"],
        )

    def test_coverage_requires_every_subsystem_but_allows_inspected_zero_control_site(self):
        pages = [PageRecord("https://one.test", "", 0, "homepage", 200, "https://one.test", "https://one.test", "text/html")]
        sufficient, status, homepage = _coverage_status(pages, 1, 1, True, True, True, [])
        self.assertTrue(homepage); self.assertTrue(sufficient); self.assertEqual(status, "coverage_sufficient")
        insufficient = _coverage_status(pages, 1, 1, False, True, True, ["revenue failed"])
        self.assertEqual(insufficient[:2], (False, "insufficient_coverage"))

    def test_coverage_sufficient_for_small_site_with_one_visited_page(self):
        # Regression: a small site whose other links are external or the homepage repeated
        # (duplicate) is fully covered at one page; it must not read as insufficient_coverage.
        pages = [PageRecord("https://one.test/", "", 0, "homepage", 200, "https://one.test/", "https://one.test/", "text/html")]
        sufficient, status, _ = _coverage_status(pages, 1, 1, True, True, True, [])
        self.assertTrue(sufficient); self.assertEqual(status, "coverage_sufficient")
        # But a browser stage that rendered nothing is still insufficient.
        none_rendered, status2, _ = _coverage_status(pages, 0, 0, True, True, True, [])
        self.assertFalse(none_rendered); self.assertEqual(status2, "insufficient_coverage")

    def test_timeout_salvages_partial_coverage_only_when_homepage_inspected(self):
        # Hang backstop: budget hit mid-scan (timed_out) with the homepage inspected -> partial, not
        # a discarded empty scan; the same incomplete scan without the timeout signal stays insufficient.
        pages = [PageRecord("https://one.test/", "", 0, "homepage", 200, "https://one.test/", "https://one.test/", "text/html")]
        salvaged = _coverage_status(pages, 1, 0, False, True, False, ["fast_audit: organization reached the 150-second limit"], timed_out=True)
        self.assertEqual(salvaged[:2], (False, "partial_coverage"))
        # Without the timeout flag the identical incomplete state is a genuine failure, not a salvage.
        not_timed_out = _coverage_status(pages, 1, 0, False, True, False, ["fast_audit: boom"])
        self.assertEqual(not_timed_out[:2], (False, "insufficient_coverage"))
        # A timeout that never even loaded the homepage cannot be salvaged.
        no_homepage = _coverage_status([], 0, 0, False, False, False, ["fast_audit: timed out"], timed_out=True)
        self.assertEqual(no_homepage[:2], (False, "insufficient_coverage"))

    def test_browser_code_never_fills_or_types_form_data(self):
        source = inspect.getsource(browser_audit)
        self.assertNotIn(".fill(", source)
        self.assertNotIn(".type(", source)

    def test_no_revenue_orchestration_does_not_invoke_stable_revenue(self):
        page = PageRecord("https://one.test", "", 0, "homepage", 200, "https://one.test", "https://one.test", "text/html")
        generic = ResultRow("One", "visible_site_failure", "https://one.test", "https://one.test", 200, "parked")
        opportunity = OpportunityRow("One", "https://one.test", "email for price", "structured inquiry", "medium", "How is this handled?")
        revenue = BrowserEvidence(
            organization="One", homepage="https://one.test", source_page="https://one.test",
            category="donation", visible_control="Donate", control_type="a",
            original_target="https://one.test/give", resulting_url="https://one.test/give",
            interaction_result="same-tab", main_document_status=404, visible_error_text="404",
            browser_or_network_error="", screenshot_path="shot.png",
            verification_result="confirmed_broken", evidence="visitor 404",
        )
        with TemporaryDirectory() as directory:
            root = Path(directory); input_path = root / "in.csv"; output = root / "out"
            input_path.write_text("organization,url\nOne,https://one.test\n")
            with patch("auditor.v2.concurrent.futures.ProcessPoolExecutor", concurrent.futures.ThreadPoolExecutor), \
                 patch("auditor.v2.crawl_inventory", return_value=([page], [], 0, 0)), \
                 patch("auditor.v2.classify_http_results", return_value=([generic], [opportunity])), \
                 patch("auditor.v2.browser_audit", return_value=([], 1, 1, 0, 0, False, None, None)), \
                 patch("auditor.v2._run_stable_revenue_verifier", return_value=[revenue]) as stable:
                findings, opportunities, coverage, summaries = run_audit_v2(input_path, output, 1, deep_revenue=False)
            stable.assert_not_called()
            self.assertEqual({row.source for row in findings}, {"generic_site_check"})
            self.assertEqual(opportunities[0].source, "automation_opportunity")
            self.assertEqual(coverage[0].coverage_status, "coverage_sufficient")
            self.assertFalse(coverage[0].deep_revenue_requested)
            self.assertEqual(summaries[0].scan_outcome, "findings_present")
            for name in ("findings.csv", "automation-opportunities.csv", "coverage.csv", "organization-summary.csv"):
                self.assertTrue((output / name).exists())
            with (output / "findings.csv").open() as handle:
                header = next(csv.reader(handle))
                self.assertIn("source", header); self.assertIn("confidence", header)

    def test_optional_deep_stage_invokes_stable_verifier_and_merges_result(self):
        page = PageRecord("https://one.test", "", 0, "homepage", 200, "https://one.test", "https://one.test", "text/html")
        revenue = BrowserEvidence(
            organization="One", homepage="https://one.test", source_page="https://one.test",
            category="homepage", visible_control="Homepage", control_type="page",
            original_target="https://one.test", resulting_url="https://one.test",
            interaction_result="same-tab", main_document_status=200, visible_error_text="parked",
            browser_or_network_error="", screenshot_path="shot.png",
            verification_result="confirmed_broken", evidence="parked",
        )
        with TemporaryDirectory() as directory:
            root = Path(directory); input_path = root / "in.csv"; input_path.write_text("organization,url\nOne,https://one.test\n")
            with patch("auditor.v2.concurrent.futures.ProcessPoolExecutor", concurrent.futures.ThreadPoolExecutor), \
                 patch("auditor.v2.crawl_inventory", return_value=([page], [], 0, 0)), \
                 patch("auditor.v2.classify_http_results", return_value=([], [])), \
                 patch("auditor.v2.browser_audit", return_value=([], 1, 1, 0, 0, False, None, None)), \
                 patch("auditor.v2._run_stable_revenue_verifier", return_value=[revenue]) as stable:
                findings, _opportunities, coverage, _summaries = run_audit_v2(input_path, root / "out", 1, True)
            stable.assert_called_once()
            self.assertEqual(findings[0].source, "revenue_path_verifier")
            self.assertTrue(coverage[0].deep_revenue_requested)
            self.assertTrue(coverage[0].deep_revenue_completed)

    def test_stable_verifier_argv_parses_against_current_cli(self):
        # Regression: v2 spawns `browser-verify` as a subprocess. If its argv carries a flag the CLI
        # no longer defines, argparse exits and the deep revenue stage silently no-ops (the error is
        # swallowed upstream). Parse the real argv against the live parser so flag drift fails here,
        # not in production, and without a live browser.
        captured = {}

        def fake_run(cmd, *args, **kwargs):
            captured["argv"] = list(cmd)
            output_dir = Path(cmd[cmd.index("--output-dir") + 1])
            header = ",".join(BrowserEvidence.__dataclass_fields__)
            (output_dir / "browser-evidence.csv").write_text(header + "\n", encoding="utf-8")

        with TemporaryDirectory() as directory:
            revenue_dir = Path(directory) / "revenue"; revenue_dir.mkdir()
            with patch("auditor.v2.subprocess.run", side_effect=fake_run):
                _run_stable_revenue_verifier(
                    "One", "https://one.test", revenue_dir, timeout=20.0,
                    deadline=time.monotonic() + 100,
                )
        argv = captured["argv"]
        self.assertEqual(argv[2:4], ["auditor", "browser-verify"])
        # The tokens after `-m auditor` must parse cleanly against the current CLI; parse_args exits
        # the process on an unknown flag, which would surface as SystemExit here.
        parsed = cli.build_parser().parse_args(argv[3:])
        self.assertEqual(parsed.command, "browser-verify")

    def test_timeout_salvages_partial_rows_and_marks_partial_not_empty(self):
        # The browser stage times out (6th return value True) after the homepage was inspected. The
        # already-gathered findings must be kept and the org marked partial_coverage, never discarded
        # as an empty insufficient_coverage scan (one slow page must not zero out the org).
        page = PageRecord("https://one.test", "", 0, "homepage", 200, "https://one.test", "https://one.test", "text/html")
        finding = ResultRow("One", "visible_site_failure", "https://one.test", "https://one.test", 200, "parked")
        opportunity = OpportunityRow("One", "https://one.test", "email for price", "inquiry", "medium", "How?")
        with TemporaryDirectory() as directory:
            root = Path(directory); input_path = root / "in.csv"; input_path.write_text("organization,url\nOne,https://one.test\n")
            with patch("auditor.v2.concurrent.futures.ProcessPoolExecutor", concurrent.futures.ThreadPoolExecutor), \
                 patch("auditor.v2.crawl_inventory", return_value=([page], [], 0, 0)), \
                 patch("auditor.v2.classify_http_results", return_value=([finding], [opportunity])), \
                 patch("auditor.v2.browser_audit", return_value=([], 1, 0, 0, 0, True, None, None)):
                findings, opportunities, coverage, summaries = run_audit_v2(input_path, root / "out", 1, deep_revenue=False)
            self.assertEqual(len(findings), 1); self.assertEqual(len(opportunities), 1)
            self.assertFalse(coverage[0].coverage_sufficient)
            self.assertEqual(coverage[0].coverage_status, "partial_coverage")
            self.assertEqual(summaries[0].scan_outcome, "findings_present")
            self.assertTrue((root / "out/coverage.csv").exists())

    def test_timeout_with_no_findings_marks_partial_coverage_outcome(self):
        # A salvaged scan that found nothing still reads as partial_coverage, not clean or insufficient.
        page = PageRecord("https://one.test", "", 0, "homepage", 200, "https://one.test", "https://one.test", "text/html")
        with TemporaryDirectory() as directory:
            root = Path(directory); input_path = root / "in.csv"; input_path.write_text("organization,url\nOne,https://one.test\n")
            with patch("auditor.v2.concurrent.futures.ProcessPoolExecutor", concurrent.futures.ThreadPoolExecutor), \
                 patch("auditor.v2.crawl_inventory", return_value=([page], [], 0, 0)), \
                 patch("auditor.v2.classify_http_results", return_value=([], [])), \
                 patch("auditor.v2.browser_audit", return_value=([], 1, 0, 0, 0, True, None, None)):
                _findings, _opps, coverage, summaries = run_audit_v2(input_path, root / "out", 1, deep_revenue=False)
            self.assertEqual(coverage[0].coverage_status, "partial_coverage")
            self.assertEqual(summaries[0].scan_outcome, "partial_coverage")

    def test_two_worker_results_flush_in_input_order(self):
        active = peak = 0; lock = threading.Lock()
        def fake(index, organization, homepage, input_path, output_dir, timeout, deep):
            nonlocal active, peak
            with lock: active += 1; peak = max(peak, active)
            time.sleep(0.04 if index == 1 else 0.01)
            with lock: active -= 1
            coverage = CoverageRow(organization, homepage, 1, 1, homepage, 0, "", 0, 0, 1, 1, 0, 0, 0, 0.01, True, "coverage_sufficient", True, True, True, True, False, False, "")
            summary = OrganizationSummaryRow(organization, homepage, 0, 0, 0, 0, "clean")
            return index, [], [], coverage, summary
        with TemporaryDirectory() as directory:
            root = Path(directory); path = root / "in.csv"
            path.write_text("organization,url\nFirst,https://first.test\nSecond,https://second.test\nThird,https://third.test\n")
            with patch("auditor.v2.concurrent.futures.ProcessPoolExecutor", concurrent.futures.ThreadPoolExecutor), \
                 patch("auditor.v2._audit_organization", side_effect=fake):
                _findings, _opps, coverage, summaries = run_audit_v2(path, root / "out", 1)
            self.assertEqual(peak, 2)
            self.assertEqual([row.organization for row in coverage], ["First", "Second", "Third"])
            self.assertEqual([row.organization for row in summaries], ["First", "Second", "Third"])


class V2EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), V2Handler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def test_bounded_crawlee_inventory_assets_and_opportunity(self):
        pages, skips, links, assets = asyncio.run(crawl_inventory(self.base, 2))
        self.assertLessEqual(len(pages), MAX_PAGES)
        self.assertTrue(any(skip.reason == "pagination_or_search_result" for skip in skips))
        self.assertTrue(any(skip.reason == "organization_product_limit" for skip in skips))
        # Broken assets are now detected during the browser render, not by the crawl; here the
        # crawl only discovers pages/links/opportunities and counts assets seen.
        rows, opportunities = classify_http_results("Fixture", pages)
        self.assertTrue(opportunities)
        self.assertGreater(links, 0); self.assertGreater(assets, 0)

    def test_crawl_salvages_visited_pages_when_a_slow_page_trips_the_deadline(self):
        # A single slow page must not zero out the crawl: pages fetched before the budget was spent
        # are returned (partial), and the slow page is dropped as an organization_timeout skip.
        deadline = time.monotonic() + 0.6
        pages, skips, _links, _assets = asyncio.run(crawl_inventory(self.base + "slow-home", 5, deadline))
        visited = [urlsplit(p.url).path for p in pages]
        self.assertIn("/slow-home", visited)              # homepage salvaged, not an empty scan
        self.assertNotIn("/slow-child", visited)          # the slow page never completed
        self.assertTrue(any(skip.reason == "organization_timeout" for skip in skips))

    def test_browser_mobile_forms_rendered_link_and_negative_control(self):
        urls = ["contact-mobile-hidden", "donate-mobile-overlay", "shop-mobile-overflow", "forms", "clean"]
        pages = [PageRecord(self.base + value, "", 0 if index == 0 else 1, "fixture", 200, self.base + value, self.base + value, "text/html") for index, value in enumerate(urls)]
        from pathlib import Path
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory:
            rows, desktop, mobile, controls, forms, timed_out, _primary, _secondary = browser_audit("Fixture", self.base, pages, Path(directory), 5)
        enrich_findings(rows)
        by_type = {row.issue_type: row for row in rows}
        kinds = set(by_type)
        self.assertIn("mobile_primary_action_unusable", kinds)
        self.assertIn("mobile_blocking_overlay", kinds)
        self.assertIn("mobile_horizontal_overflow", kinds)
        self.assertIn("interface_broken", kinds)
        self.assertIn("interface_usable_submission_not_tested", kinds)
        self.assertIn("failed_iframe_widget", kinds)
        self.assertIn("rendered_only_link_discovered", kinds)
        self.assertEqual(by_type["failed_iframe_widget"].confidence, "high")
        # shop-mobile-overflow is wide only at the phone viewport (desktop 1440 does not overflow),
        # so the mobile-only gate promotes it to high; the offscreen primary action stays medium.
        self.assertEqual(by_type["mobile_horizontal_overflow"].confidence, "high")
        self.assertEqual(by_type["mobile_horizontal_overflow"].context, "mobile")
        self.assertEqual(by_type["mobile_primary_action_unusable"].confidence, "medium")
        self.assertEqual(by_type["interface_usable_submission_not_tested"].confidence, "low")
        self.assertFalse(any(row.source_url.endswith("/clean") for row in rows))
        self.assertLessEqual(desktop, 6); self.assertLessEqual(mobile, 3); self.assertGreater(controls, 0); self.assertGreater(forms, 0)
        self.assertFalse(timed_out)

    def test_mobile_overflow_is_high_only_when_desktop_is_clean(self):
        # Two homepages rendered independently: one overflows only at the phone viewport (mobile-only
        # -> high), one overflows at every viewport (not additive over a desktop finding -> suppressed).
        def overflow_kinds(path):
            pages = [PageRecord(self.base + path, "", 0, "fixture", 200, self.base + path, self.base + path, "text/html")]
            with TemporaryDirectory() as directory:
                rows, *_rest = browser_audit("Fixture", self.base + path, pages, Path(directory), 5)
            enrich_findings(rows)
            return {row.issue_type: row for row in rows}

        mobile_only = overflow_kinds("shop-mobile-overflow")
        self.assertIn("mobile_horizontal_overflow", mobile_only)
        self.assertEqual(mobile_only["mobile_horizontal_overflow"].confidence, "high")

        both = overflow_kinds("overflow-both")
        self.assertNotIn("mobile_horizontal_overflow", both)  # desktop also overflows -> not mobile-only

    def test_mobile_nav_unopenable_when_hamburger_fails_to_open(self):
        # Nav (with Donate) is visible at desktop; a media query hides it at mobile and the hamburger
        # is inert, so tapping the menu reveals nothing. This is a heuristic signal (a collapsed menu
        # that will not open), reported at MEDIUM for review — never a high-confidence datum claim,
        # because per-name reachability proved unreliable on real sites whose menus open fine.
        pages = [PageRecord(self.base + "broken-hamburger", "", 0, "fixture", 200, self.base + "broken-hamburger", self.base + "broken-hamburger", "text/html")]
        with TemporaryDirectory() as directory:
            rows, *_rest = browser_audit("Fixture", self.base + "broken-hamburger", pages, Path(directory), 5)
        enrich_findings(rows)
        unopenable = [row for row in rows if row.issue_type == "mobile_nav_unopenable"]
        self.assertTrue(unopenable, "expected a mobile_nav_unopenable finding")
        self.assertTrue(all(row.confidence == "medium" and row.context == "mobile" for row in unopenable))

    def test_mobile_only_broken_asset_is_flagged_high_and_deduped_from_desktop(self):
        # A <picture> whose mobile <source> 404s only at the phone breakpoint; desktop loads the 200
        # <img> fallback, so the desktop pass sees no breakage and the mobile pass flags it alone.
        pages = [PageRecord(self.base + "mobile-broken-asset", "", 0, "fixture", 200, self.base + "mobile-broken-asset", self.base + "mobile-broken-asset", "text/html")]
        with TemporaryDirectory() as directory:
            rows, *_rest = browser_audit("Fixture", self.base + "mobile-broken-asset", pages, Path(directory), 5)
        enrich_findings(rows)
        mobile_broken = [row for row in rows if row.issue_type == "mobile_broken_image"]
        self.assertTrue(mobile_broken, "expected a mobile_broken_image finding")
        self.assertTrue(all(row.confidence == "high" and row.context == "mobile" for row in mobile_broken))
        self.assertTrue(any(row.failed_url.endswith("/missing-mobile.png") for row in mobile_broken))
        # The same asset must NOT be double-reported as a desktop broken asset.
        self.assertFalse(any(row.issue_type == "broken_image" and row.failed_url.endswith("/missing-mobile.png") for row in rows))

    def test_browser_flags_broken_assets_from_render(self):
        # The homepage embeds /missing.png (404) and a stylesheet whose background is /missing-bg.png
        # (404); the render fetches both and the response listener flags them, no separate HTTP pass.
        pages = [PageRecord(self.base, "", 0, "fixture", 200, self.base, self.base, "text/html")]
        with TemporaryDirectory() as directory:
            rows, *_rest = browser_audit("Fixture", self.base, pages, Path(directory), 5)
        enrich_findings(rows)
        broken = [row for row in rows if row.issue_type == "broken_image"]
        self.assertTrue(any(row.failed_url.endswith("/missing.png") for row in broken))
        self.assertTrue(broken and all(row.confidence == "high" for row in broken))

    def test_rendered_image_still_loading_is_not_flagged(self):
        pages = [PageRecord(self.base + "image-loading", "", 0, "fixture", 200, self.base + "image-loading", self.base + "image-loading", "text/html")]
        with TemporaryDirectory() as directory:
            rows, *_rest = browser_audit("Fixture", self.base, pages, Path(directory), 5)
        self.assertFalse(any(row.issue_type == "rendered_broken_image" for row in rows))

    def test_rendered_image_completed_with_zero_dimensions_is_flagged(self):
        pages = [PageRecord(self.base + "image-broken", "", 0, "fixture", 200, self.base + "image-broken", self.base + "image-broken", "text/html")]
        with TemporaryDirectory() as directory:
            rows, *_rest = browser_audit("Fixture", self.base, pages, Path(directory), 5)
        enrich_findings(rows)
        broken = [row for row in rows if row.issue_type == "rendered_broken_image"]
        self.assertEqual(len(broken), 1)
        self.assertTrue(broken[0].failed_url.endswith("/broken.png"))
        self.assertEqual(broken[0].evidence, "Visible rendered image finished loading with zero natural dimensions")
        self.assertEqual(broken[0].confidence, "high")

    def test_detach_iframes_drops_subframes_before_control_discovery(self):
        # discover_controls iterates page.frames with untimed calls; a busy embed hangs it.
        # _detach_iframes must remove subframes so only the main frame remains.
        import shutil
        from playwright.sync_api import sync_playwright
        executable = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
        launch = {"headless": True, "args": ["--disable-dev-shm-usage"]}
        if executable:
            launch["executable_path"] = executable
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**launch)
            page = browser.new_context().new_page()
            page.set_default_timeout(5000)
            page.goto(self.base + "iframes", wait_until="domcontentloaded")
            page.wait_for_timeout(400)
            self.assertGreater(len(page.frames), 1)
            _detach_iframes(page)
            self.assertEqual(len(page.frames), 1)
            browser.close()

    def test_soft_rebuilding_parked_and_clean_classification(self):
        pages = []
        for name in ("soft", "rebuilding", "parked", "clean"):
            status, _kind, body = V2HandlerRoutes(name)
            pages.append(PageRecord(self.base + name, "", 1, "fixture", status, self.base + name, self.base + name, "text/html", body))
        rows, _opportunities = classify_http_results("Fixture", pages)
        enrich_findings(rows)
        flagged = {row.source_url.rsplit("/", 1)[-1] for row in rows}
        self.assertEqual(flagged, {"soft", "rebuilding", "parked"})
        self.assertTrue(all(row.confidence == "medium" for row in rows))


class _BotWallHandler(BaseHTTPRequestHandler):
    """403s any request whose User-Agent is not a real Chrome, and serves a normal homepage
    otherwise (reproduces a real bot-walled site: crawlee's default
    Firefox-impersonation UA -> 403 empty scan, a Chrome UA -> 200 full page)."""

    def do_GET(self):
        if "Chrome" not in (self.headers.get("User-Agent") or ""):
            self.send_response(403); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(b"Forbidden")
            return
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(b'<a href="/donate">Donate</a><a href="/contact">Contact</a>')

    def log_message(self, *_args): pass


class V2BotWallCrawlTests(unittest.TestCase):
    """A site that 403s a bot UA but serves fine to a browser must still be crawled, not come
    back empty. The main crawl impersonates Chrome so bot-walled-but-browser-accessible orgs are
    scanned instead of scored insufficient_coverage."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _BotWallHandler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def test_chrome_impersonation_crawls_a_bot_walled_homepage(self):
        pages, _skips, links, _assets = asyncio.run(crawl_inventory(self.base, 5))
        homepage = next((page for page in pages if page.depth == 0), None)
        self.assertIsNotNone(homepage)
        # Without Chrome impersonation the homepage 403s, no links parse, and the org is empty.
        self.assertEqual(homepage.status_code, 200)
        self.assertFalse(homepage.error)
        self.assertGreater(links, 0)


def V2HandlerRoutes(name):
    bodies = {"soft": "Page not found. Return home.", "rebuilding": "We are rebuilding our website.", "parked": "This domain is for sale.", "clean": "Welcome. Ordinary public information."}
    return 200, "text/html", bodies[name]


class Gate1DomainMigrationTests(unittest.TestCase):
    """Gate 1: a homepage that 3xx-forwards to a different host is a migrated domain; its legacy
    404s must not be emitted as the org's visitor-visible failures (reproduces real domain
    migrations: a legacy host 3xx-forwards to a different host)."""

    def setUp(self):
        self.new = ThreadingHTTPServer(("127.0.0.1", 0), _NewSiteHandler)
        self.new_thread = Thread(target=self.new.serve_forever, daemon=True); self.new_thread.start()
        self.new_base = f"http://127.0.0.1:{self.new.server_port}/"
        redirect_to = self.new_base
        # Old domain: homepage 301s off-host; a legacy nav path still 404s on the abandoned origin.
        class _OldSiteHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/":
                    self.send_response(301); self.send_header("Location", redirect_to); self.end_headers(); return
                self.send_response(404); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(b"Not found")
            def log_message(self, *_a): pass
        self.old = ThreadingHTTPServer(("127.0.0.1", 0), _OldSiteHandler)
        self.old_thread = Thread(target=self.old.serve_forever, daemon=True); self.old_thread.start()
        self.old_base = f"http://127.0.0.1:{self.old.server_port}/"
        self.old_host = f"127.0.0.1:{self.old.server_port}"

    def tearDown(self):
        for server, thread in ((self.old, self.old_thread), (self.new, self.new_thread)):
            server.shutdown(); server.server_close(); thread.join()

    def test_resolve_canonical_homepage_detects_cross_host_redirect(self):
        canonical, migrated_from = resolve_canonical_homepage(self.old_base, timeout=5)
        self.assertEqual(migrated_from, self.old_host)
        self.assertEqual(normalize_inventory_url(canonical), normalize_inventory_url(self.new_base))
        # A same-site (www) redirect is not a migration.
        _canonical, not_migrated = resolve_canonical_homepage(self.new_base, timeout=5)
        self.assertEqual(not_migrated, "")

    def test_migration_drops_origin_findings_and_emits_one_marker(self):
        _canonical, migrated_from = resolve_canonical_homepage(self.old_base, timeout=5)
        legacy = ResultRow("Org", "page_http_failure", self.old_base, f"{self.old_base}donate", 404, "Visitor page returned HTTP 404")
        legacy2 = ResultRow("Org", "visible_site_failure", f"{self.old_base}donate", f"{self.old_base}donate", 404, "404 Not Found")
        current = ResultRow("Org", "rendered_broken_image", self.new_base, f"{self.new_base}logo.png", "", "broken image on the live site")
        rows = suppress_origin_findings([legacy, legacy2, current], migrated_from)
        rows.append(migration_finding("Org", self.old_base, self.new_base))
        enrich_findings(rows)
        # No finding survives on the abandoned origin; the live-site finding does.
        self.assertNotIn(self.old_host, {urlsplit(r.failed_url).netloc for r in rows if r.issue_type != "origin_domain_migrated"})
        self.assertIn("rendered_broken_image", {r.issue_type for r in rows})
        markers = [r for r in rows if r.issue_type == "origin_domain_migrated"]
        self.assertEqual(len(markers), 1)
        self.assertEqual(markers[0].confidence, "low")  # never a high-confidence visitor-visible failure


class _NewSiteHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(b'<header><a href="/donate/">Donate</a></header>Welcome to the current site')
    def log_message(self, *_a): pass


class Gate2NavReachabilityTests(unittest.TestCase):
    """Gate 2: a dead link is high-confidence visitor-visible only when the live rendered homepage
    nav reaches it. Reproduces a batch of real false positives where a body-only 404 or a
    trailing-slash nav variant was wrongly flagged as a visitor-visible dead link."""

    def test_gate_ranks_dead_links_by_live_nav_reachability(self):
        primary_nav = {normalize_inventory_url("https://x.test/broken-nav-target/")}
        secondary_nav = {normalize_inventory_url("https://x.test/old-report/")}
        in_nav = ResultRow("X", "dead_link", "https://x.test/", "https://x.test/broken-nav-target", 404, "HTTP 404")
        footer = ResultRow("X", "dead_link", "https://x.test/", "https://x.test/old-report", 404, "HTTP 404")
        # A body-only reference: /programs is an inline body link, not in the nav.
        body_only = ResultRow("X", "page_http_failure", "https://x.test/", "https://body.test/programs", 404, "HTTP 404")
        # A trailing-slash variant: /special-events 404s but the nav links /special-events/ (200) -> noise.
        variant = ResultRow("X", "page_http_failure", "https://x.test/", "https://variant.test/special-events", 404, "HTTP 404")
        untouched = ResultRow("X", "rendered_broken_image", "https://x.test/", "https://x.test/logo.png", "", "broken")
        rows = [in_nav, footer, body_only, variant, untouched]
        with patch("auditor.v2._variant_is_ok", side_effect=lambda url, timeout=5: url.endswith("/special-events")):
            apply_nav_reachability_gate(rows, primary_nav, secondary_nav, timeout=1)
        self.assertEqual(in_nav.confidence, "high")
        self.assertEqual(footer.confidence, "medium")
        self.assertEqual(body_only.confidence, "low")
        self.assertEqual(variant.confidence, "low")
        self.assertIn("canonicalization noise", variant.evidence)
        self.assertIn("footer", footer.evidence)
        # Non-dead-link findings are untouched by the nav gate.
        self.assertEqual(untouched.confidence, "")

    def test_gate_is_a_noop_when_homepage_never_rendered(self):
        dead = ResultRow("X", "dead_link", "https://x.test/", "https://x.test/gone", 404, "HTTP 404")
        apply_nav_reachability_gate([dead], None, None, timeout=1)
        self.assertEqual(dead.confidence, "")  # left for enrich_findings -> high; not falsely cleared


class Gate2TrailingSlashVariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), V2Handler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def test_variant_probe_distinguishes_slash_noise_from_dead_target(self):
        # /special-events/ serves 200 on the fixture; the bare /special-events does not.
        self.assertTrue(_variant_is_ok(self.base + "special-events", timeout=3))
        # /programs has no working slashed sibling -> a genuinely dead target, not noise.
        self.assertFalse(_variant_is_ok(self.base + "programs", timeout=3))
        # The slash variant may 301 to a working page (bare host -> www); a visitor still lands on
        # 200, so this is canonicalization noise. The probe must follow the redirect.
        self.assertTrue(_variant_is_ok(self.base + "redir-variant", timeout=3))


if __name__ == "__main__": unittest.main()
