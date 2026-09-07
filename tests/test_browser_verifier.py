import csv
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from auditor.browser_verifier import (
    Control,
    EcommerceTraversalState,
    all_organizations,
    classify_control,
    decide_result,
    discover_controls,
    ecommerce_destination_allowed,
    ecommerce_destination_kind,
    filter_ecommerce_controls,
    find_explicit_failure,
    find_visible_error,
    is_terminal_interface,
    is_intentional_non_web_action,
    normalize_destination,
    run_browser_validation,
    should_visit_destination,
)
from auditor.cli import build_parser


class BrowserClassificationTests(unittest.TestCase):
    def test_ecommerce_budget_persists_across_destination_pages(self):
        state = EcommerceTraversalState()
        self.assertTrue(ecommerce_destination_allowed(
            state, "https://shop.example/category/art", reserve=True,
        ))
        self.assertFalse(ecommerce_destination_allowed(
            state, "https://shop.example/category/jewelry", reserve=True,
        ))
        self.assertTrue(ecommerce_destination_allowed(
            state, "https://shop.example/product/one", reserve=True,
        ))
        self.assertFalse(ecommerce_destination_allowed(
            state, "https://shop.example/product/two", reserve=True,
        ))
        self.assertFalse(ecommerce_destination_allowed(
            state, "https://shop.example/category/art?page=2", reserve=True,
        ))

    def test_cart_and_checkout_have_independent_budgets(self):
        state = EcommerceTraversalState()
        for url, expected in (
            ("https://shop.example/category/art", "listing"),
            ("https://shop.example/product/one", "product"),
            ("https://shop.example/cart", "cart"),
            ("https://shop.example/checkout", "checkout"),
        ):
            self.assertEqual(ecommerce_destination_kind(url), expected)
            self.assertTrue(ecommerce_destination_allowed(state, url, reserve=True))

    def test_inventory_page_keeps_one_product_and_one_add_to_cart(self):
        def control(name, target):
            return Control("ecommerce", name, "a", target, "https://shop.example/category/art", "", 0, 0, False)
        controls = [
            control("Artwork One", "https://shop.example/product/one"),
            control("Artwork Two", "https://shop.example/product/two"),
            control("Add to Cart", "https://shop.example/product/one"),
            control("Add to Cart", "https://shop.example/product/two"),
            control("Cart", "https://shop.example/cart"),
            control("Checkout", "https://shop.example/checkout"),
        ]
        kept = filter_ecommerce_controls(
            controls, "https://shop.example/category/art", EcommerceTraversalState(),
        )
        self.assertEqual([item.name for item in kept], [
            "Artwork One", "Add to Cart", "Cart", "Checkout",
        ])

    def test_nested_shop_product_records_one_add_to_cart_with_org_limits(self):
        state = EcommerceTraversalState()
        listing = "https://art.example/shop/?product_tag=fine-art"
        product = "https://art.example/shop/artist/artwork-title/"
        self.assertTrue(ecommerce_destination_allowed(state, listing, reserve=True))
        self.assertTrue(ecommerce_destination_allowed(state, product, reserve=True))
        self.assertEqual(ecommerce_destination_kind(product), "product")
        controls = [
            Control("ecommerce", "Add to cart", "button", "", product, "", 0, 0, True),
            Control("ecommerce", "Add to cart", "button", "", product, "", 0, 1, True),
        ]
        kept = filter_ecommerce_controls(controls, product, state)
        self.assertEqual([control.name for control in kept], ["Add to cart"])
        self.assertTrue(state.add_to_cart_evaluated)
        self.assertFalse(ecommerce_destination_allowed(
            state, "https://art.example/shop/another-artist/second-work/", reserve=True,
        ))

    def test_each_organization_gets_independent_ecommerce_budget(self):
        first = EcommerceTraversalState()
        second = EcommerceTraversalState()
        self.assertTrue(ecommerce_destination_allowed(first, "https://one.example/shop", reserve=True))
        self.assertFalse(ecommerce_destination_allowed(first, "https://one.example/category/two", reserve=True))
        self.assertTrue(ecommerce_destination_allowed(second, "https://two.example/category/two", reserve=True))

    def test_non_ecommerce_controls_are_unaffected(self):
        controls = [
            Control("donation", "Donate", "a", "https://example.org/give", "https://example.org", "", 0, 0, False),
            Control("contact", "Contact", "a", "https://example.org/contact", "https://example.org", "", 0, 1, False),
        ]
        self.assertEqual(filter_ecommerce_controls(
            controls, "https://example.org", EcommerceTraversalState(),
        ), controls)

    def test_browser_verify_scans_all_input_without_a_selector(self):
        args = build_parser().parse_args(["browser-verify", "arbitrary.csv"])
        self.assertEqual(str(args.input_csv), "arbitrary.csv")

    def test_all_selector_preserves_every_input_organization(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "organizations.csv"
            path.write_text(
                "organization,url\nExample Org,https://one.example\nOther,https://two.example\n"
            )
            self.assertEqual(all_organizations(path), ("Example Org", "Other"))

    def test_classifies_only_control_names_and_titles(self):
        cases = {
            "Donate Now": "donation",
            "Support Us": "donation",
            "Box Office": "ticket",
            "RSVP": "registration",
            "Become a Member": "membership",
            "Contact Us": "contact",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(classify_control(name), expected)
        self.assertIsNone(classify_control("July 14"))
        self.assertIsNone(classify_control("Next", "calendar navigation"))
        self.assertEqual(classify_control("Buy", "Tickets"), "ticket")
        self.assertEqual(
            classify_control("Did you know? Please", target="https://example.org/support-us.html"),
            "donation",
        )
        self.assertIsNone(classify_control("July 14", target="https://example.org/calendar/event/14"))
        self.assertIsNone(classify_control("CALENDAR", target="https://example.org/tickets/calendar"))
        self.assertIsNone(classify_control("", target="https://example.org/donate"))
        self.assertIsNone(classify_control("Join Our Mailing List"))

    def test_gallery_inquiry_and_ecommerce_labels(self):
        cases = {
            "Request More Information": "contact",
            "Inquire": "contact",
            "Schedule a Call": "contact",
            "Make a Reservation": "contact",
            "Price Request": "contact",
            "Artwork Inquiry": "contact",
            "SHOP HERE": "ecommerce",
            "PURCHASE": "ecommerce",
            "Add to Cart": "ecommerce",
            "Add to Pouch": "ecommerce",
            "CHECKOUT": "ecommerce",
        }
        for label, expected in cases.items():
            with self.subTest(label=label):
                self.assertEqual(classify_control(label), expected)

    def test_destination_page_terminal_form_controls_use_context(self):
        self.assertEqual(
            classify_control("Send Message", surrounding_context="Contact Name Email Message"),
            "contact",
        )
        self.assertEqual(
            classify_control("Apply", target="https://example.org/membership", surrounding_context="Membership"),
            "membership",
        )
        self.assertEqual(classify_control("Make a Gift"), "donation")

    def test_account_and_newsletter_join_false_positives(self):
        self.assertIsNone(classify_control(
            "Create account", target="https://shop.example/account/register",
        ))
        self.assertIsNone(classify_control(
            "JOIN!", surrounding_context="Join our mailing list Email Subscribe",
        ))

    def test_unrelated_educational_registration_false_positives(self):
        context = "College Students Academics Education"
        for label in (
            "Register", "Apply Now", "Returning Student Registration",
            "High School Equivalency/GED", "Student Orientation",
            "Registration and Payment Deadlines",
        ):
            with self.subTest(label=label):
                self.assertIsNone(classify_control(label, surrounding_context=context))
        self.assertEqual(
            classify_control("Register", surrounding_context="Broom Workshop Event"),
            "registration",
        )

    def test_destination_normalization_and_depth_visited_limits(self):
        self.assertEqual(
            normalize_destination("HTTPS://Example.COM:443/shop/#items"),
            "https://example.com/shop",
        )
        visited = {"https://example.com/shop"}
        self.assertFalse(should_visit_destination("https://example.com/shop/", 1, visited))
        self.assertTrue(should_visit_destination("https://example.com/product/one", 2, visited))
        self.assertFalse(should_visit_destination("https://example.com/product/two", 3, visited))
        self.assertFalse(should_visit_destination("mailto:gallery@example.com", 1, visited))

    def test_bounded_second_hop_allows_each_normalized_destination_once(self):
        visited = {normalize_destination("https://example.org")}
        first_hop = "https://example.org/shop"
        second_hop = "https://checkout.example/cart"
        self.assertTrue(should_visit_destination(first_hop, 1, visited))
        visited.add(normalize_destination(first_hop))
        self.assertFalse(should_visit_destination(first_hop + "/", 1, visited))
        self.assertTrue(should_visit_destination(second_hop, 2, visited))
        self.assertFalse(should_visit_destination(second_hop + "/checkout", 3, visited))

    def test_known_third_party_transaction_interfaces_are_terminal(self):
        for url in (
            "https://tickets.holdmyticket.com/tickets/1",
            "https://runsignup.com/TicketEvent/Test/Register",
            "https://secure.qgiv.com/for/example/event/test",
            "https://crm.bloomerang.co/HostedDonation?id=1",
            "https://example.app.neoncrm.com/membershipJoin.jsp",
            "https://my.onecause.com/fundraiser/example",
        ):
            with self.subTest(url=url):
                self.assertTrue(is_terminal_interface(url))
        self.assertFalse(is_terminal_interface("https://foundation.example.org/give"))

    def test_discovers_qualifying_controls_inside_iframes(self):
        class Element:
            def __init__(self, values):
                self.values = values
            def is_visible(self): return True
            def is_enabled(self): return True
            def evaluate(self, _script): return self.values

        class Elements:
            def __init__(self, values): self.values = values
            def count(self): return len(self.values)
            def nth(self, index): return Element(self.values[index])

        class Frame:
            def __init__(self, url, values): self.url, self.values = url, values
            def locator(self, _selector): return Elements(self.values)

        defaults = {
            "tag": "button", "role": "", "aria": "", "title": "", "alt": "",
            "href": "", "type": "button", "inForm": False, "context": "Donation form",
        }
        main = Frame("https://example.org", [])
        iframe = Frame("https://donor.example/embed", [defaults | {"text": "Donate"}])
        page = type("Page", (), {
            "url": "https://example.org", "frames": [main, iframe], "main_frame": main,
        })()
        controls = discover_controls(page)
        self.assertEqual([(row.name, row.frame_url) for row in controls], [
            ("Donate", "https://donor.example/embed"),
        ])

    def test_shop_listing_filters_are_not_controls(self):
        class Element:
            def __init__(self, values): self.values = values
            def is_visible(self): return True
            def is_enabled(self): return True
            def evaluate(self, _script): return self.values

        class Elements:
            def __init__(self, values): self.values = values
            def count(self): return len(self.values)
            def nth(self, index): return Element(self.values[index])

        defaults = {
            "tag": "a", "role": "", "aria": "", "title": "", "alt": "",
            "type": "", "inForm": False, "context": "Gift Shop",
        }
        values = [
            defaults | {"text": "BOOKS", "href": "https://example.org/gift-shop?category=books"},
            defaults | {"text": "PRINTS", "href": "https://example.org/gift-shop/prints"},
            defaults | {"text": "Example artwork", "href": "https://example.org/hsff-gift-shop/p/example"},
            defaults | {"text": "PURCHASE", "href": "https://example.org/hsff-gift-shop/p/second"},
            defaults | {"text": "PURCHASE", "href": "https://example.org/cart"},
        ]
        frame = type("Frame", (), {
            "url": "https://example.org/gift-shop",
            "locator": lambda self, _selector: Elements(values),
        })()
        page = type("Page", (), {
            "url": "https://example.org/gift-shop", "frames": [frame], "main_frame": frame,
        })()
        self.assertEqual(
            [control.name for control in discover_controls(page)],
            ["PURCHASE"],
        )

    def test_non_web_actions_are_intentional(self):
        for target in ("mailto:hello@example.org", "tel:+15055551212", "webcal://example.org/events"):
            with self.subTest(target=target):
                self.assertTrue(is_intentional_non_web_action(target))

class BrowserDecisionTests(unittest.TestCase):
    def decision(self, **overrides):
        values = {
            "status": 200,
            "navigation_error": "",
            "visible_error": "",
            "submit_risk": False,
            "non_web_action": False,
            "interaction_result": "same-tab",
        }
        values.update(overrides)
        return decide_result(**values)[0]

    def test_confirms_only_visitor_visible_failure_evidence(self):
        self.assertEqual(self.decision(status=404), "confirmed_broken")
        self.assertEqual(self.decision(status=503), "confirmed_broken")
        self.assertEqual(self.decision(navigation_error="net::ERR_NAME_NOT_RESOLVED"), "confirmed_broken")
        self.assertEqual(self.decision(visible_error="Page not found"), "confirmed_broken")

    def test_avoids_known_false_confirmations(self):
        self.assertEqual(self.decision(status=403), "needs_manual_review")
        self.assertEqual(self.decision(navigation_error="Locator.click: Timeout exceeded"), "needs_manual_review")
        self.assertEqual(self.decision(status=405, submit_risk=True), "needs_manual_review")
        self.assertEqual(self.decision(non_web_action=True), "appears_functional")
        self.assertEqual(self.decision(interaction_result="modal"), "appears_functional")

    def test_visible_error_text_is_conservative(self):
        self.assertIn("Page not found", find_visible_error("Sorry — Page not found. Return home."))
        self.assertEqual(find_visible_error("Contact us if you encounter an error."), "")
        self.assertEqual(
            find_visible_error("Oops! Something went wrong. This page didn't load Google Maps correctly. See details."),
            "",
        )
        self.assertIn("An Error Has Occurred", find_visible_error("An Error Has Occurred. Refresh the page."))

    def test_explicit_parked_and_rebuilding_failures(self):
        self.assertIn(
            "parked free",
            find_explicit_failure(
                "example.org is parked free, courtesy of the registrar.",
                "https://example.org/lander",
            ),
        )
        self.assertIn(
            "rebuilding",
            find_explicit_failure(
                "We are rebuilding our site. Please check back later.",
                "https://example.org/",
            ).lower(),
        )

    def test_test_form_requires_explicit_donation_evidence(self):
        self.assertTrue(find_explicit_failure(
            "Donation test mode", "https://giving.example/test-form34", "donation",
        ))
        self.assertEqual(find_explicit_failure(
            "Donate $0 USD Enter an amount", "https://paypal.com/donate", "donation",
        ), "")
        self.assertEqual(find_explicit_failure(
            "Demo exhibition", "https://gallery.example/demo", "contact",
        ), "")

    def test_normal_zero_control_and_cross_domain_content_are_not_failures(self):
        self.assertEqual(find_explicit_failure(
            "Welcome to our organization. Learn about our programs.",
            "https://organization.example/",
        ), "")
        self.assertEqual(find_explicit_failure(
            "Secure donation form. Choose an amount to support the organization.",
            "https://legitimate-giving.example/form", "donation",
        ), "")


class BrowserFixtureHandler(BaseHTTPRequestHandler):
    refused_port = 0

    def do_GET(self):
        routes = {
            "/parked-home": "example.org is parked free. Get This Domain. Related Search Topics: Real Estate and Cheap Airfare.",
            "/test-home": '<h1>Community Foundation</h1><a href="/test-form34">Donate</a>',
            "/test-form34": "<h1>Donation TEST MODE</h1><p>This is test-form34. Test gifts only.</p>",
            "/redirect-home": '<h1>Arts Organization</h1><a href="/redirect-parked">Donate</a>',
            "/redirect-parked": "redirect",
            "/parked-destination": "This domain is for sale. Related searches: car insurance and vacation packages.",
            "/unreachable-home": (
                '<h1>Community Museum</h1><a href="http://127.0.0.1:'
                f'{type(self).refused_port}/donate">Donate</a>'
            ),
            "/rebuilding-home": "<h1>Community Arts Center</h1><p>We are rebuilding our site. Please check back later.</p>",
            "/ordinary-home": "<h1>Community Archive</h1><p>Public history and educational resources.</p>",
            "/handoff-home": '<h1>Community Gallery</h1><a href="/legitimate-redirect">Donate</a>',
            "/legitimate-redirect": "redirect-legitimate",
            "/legitimate-handoff": "<h1>Secure Giving</h1><p>Choose an amount to support Community Gallery.</p>",
            "/zero-home": '<h1>Community Cinema</h1><a href="/variable-amount">Donate</a>',
            "/variable-amount": "<h1>Donate</h1><p>$0 USD</p><label>Enter an amount</label>",
        }
        body = routes.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        if self.path == "/redirect-parked":
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://localhost:{self.server.server_port}/parked-destination",
            )
            self.end_headers()
            return
        if self.path == "/legitimate-redirect":
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://localhost:{self.server.server_port}/legitimate-handoff",
            )
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, _format, *args):
        pass


class BrowserFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import playwright.sync_api  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("Playwright browser fixture tests require the Docker runtime")
        refused = ThreadingHTTPServer(("127.0.0.1", 0), BrowserFixtureHandler)
        BrowserFixtureHandler.refused_port = refused.server_port
        refused.server_close()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), BrowserFixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_controlled_browser_regression_and_negative_fixtures(self):
        cases = (
            ("Fixture Parked Homepage", "/parked-home"),
            ("Fixture Test Donation", "/test-home"),
            ("Fixture Redirect Parked", "/redirect-home"),
            ("Fixture Unreachable Donation", "/unreachable-home"),
            ("Fixture Rebuilding Homepage", "/rebuilding-home"),
            ("Negative Ordinary Zero Controls", "/ordinary-home"),
            ("Negative Legitimate Handoff", "/handoff-home"),
            ("Negative Variable Amount", "/zero-home"),
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "fixtures.csv"
            with input_path.open("w", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(("organization", "url"))
                writer.writerows((name, self.base + path) for name, path in cases)
            output_dir = Path(os.environ.get(
                "AUDITOR_FIXTURE_OUTPUT_DIR", root / "evidence",
            ))
            evidence, summaries = run_browser_validation(
                input_path, output_dir, tuple(name for name, _ in cases), 5,
            )
            by_name = {row.organization: row for row in summaries}
            for name, _path in cases[:5]:
                with self.subTest(name=name):
                    self.assertGreaterEqual(by_name[name].confirmed_broken, 1)
                    screenshots = [
                        row.screenshot_path for row in evidence
                        if row.organization == name and row.verification_result == "confirmed_broken"
                    ]
                    self.assertTrue(screenshots)
                    self.assertTrue(all(Path(path).is_file() for path in screenshots))
            for name, _path in cases[5:]:
                with self.subTest(name=name):
                    self.assertEqual(by_name[name].confirmed_broken, 0)


if __name__ == "__main__":
    unittest.main()
