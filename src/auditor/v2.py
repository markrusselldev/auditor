from __future__ import annotations

import asyncio
import concurrent.futures
import csv
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import timedelta
from html.parser import HTMLParser
from http.client import InvalidURL
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request as UrlRequest, urlopen

from auditor.browser_verifier import (
    BrowserEvidence,
    EcommerceTraversalState,
    discover_controls,
    filter_ecommerce_controls,
    find_explicit_failure,
    find_visible_error,
    normalize_destination,
)
from auditor import security
from auditor.scanner import read_organizations

MAX_PAGES = 12
MAX_DEPTH = 2
TRACKING_KEYS = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source"}
REJECT_QUERY = re.compile(r"^(?:page|paged|p|sort|filter|order|view|search|s|q|date|month|year)$", re.I)
PRIORITY = re.compile(
    r"donat|giv|ticket|event|register|contact|inquir|appointment|visit|member|"
    r"shop|cart|checkout|program|application|about|staff",
    re.I,
)
LISTING = re.compile(r"/(?:shop|store|inventory|collections?|category|events?)/?$", re.I)
PRODUCT = re.compile(r"/(?:products?|product-page|p)/[^/]+/?$", re.I)
CALENDAR = re.compile(r"/(?:calendar|events?)(?:/|$)", re.I)
DOCUMENT_EXT = re.compile(r"\.(?:pdf|docx?|xlsx?|zip)(?:$|\?)", re.I)
ASSET_EXT = re.compile(r"\.(?:css|js|woff2?|ttf|otf|pdf|docx?|xlsx?|zip)(?:$|\?)", re.I)
CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")]+)", re.I)
# A real crawl target carries no whitespace or ASCII control characters. Pages sometimes link prose
# as an href (a headline linked as text): one site linked a full headline sentence as an href,
# and urllib raised InvalidURL ("URL can't contain control characters")
# on the space, aborting the whole org's scan. Reject such strings before they are ever enqueued.
INVALID_URL_CHARS = re.compile(r"[\s\x00-\x1f\x7f]")
OPPORTUNITY_PATTERNS = (
    (re.compile(r"download.{0,80}(?:form|application).{0,120}(?:email|send)", re.I | re.S), "Digitize document-and-email intake"),
    (re.compile(r"(?:email|call).{0,80}(?:price|availability|reservation|appointment)", re.I | re.S), "Provide structured online inquiry or scheduling"),
    (re.compile(r"(?:submit|application).{0,100}(?:pdf|doc|email)", re.I | re.S), "Replace document-routed submission workflow"),
)
REVENUE_PATH = re.compile(r"donat|ticket|event|contact|checkout|cart", re.I)
SSL_ERROR = re.compile(r"certificate|CERTIFICATE_VERIFY|ssl|\btls\b", re.I)
# A real visitor's browser, not a bot UA: the accuracy gates verify reachability the way a person
# hits the live site, and a bot UA both gets 403-walled and can resolve redirects differently.
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
# Phone viewport for the mobile render pass: 390x844 is the iPhone 12-15 logical size, in the
# ~375-430px band that is the majority of real web traffic. Failures visible only here are what a
# phone visitor actually hits and a desktop-only render misses.
MOBILE_VIEWPORT = {"width": 390, "height": 844}

# Confidence = how strongly the failure was verified, independent of business severity.
# high: independently reproducible/observed. medium: a single heuristic signal.
# low: informational, inconclusive, or not itself a failure.
HIGH_CONFIDENCE_ISSUES = frozenset({
    "page_navigation_failure", "page_http_failure", "ssl_certificate_failure",
    "browser_page_unreachable", "rendered_page_failure", "rendered_broken_image",
    "failed_iframe_widget", "dead_link",
    # Mobile-only failures verified against a clean desktop baseline: a deterministic in-page layout
    # measurement (overflow) or a network fact (asset 404 only at the mobile breakpoint). These carry
    # the same verification strength as their desktop equivalents. Navigation/menu reachability and
    # tap-target checks are heuristic (mobile_nav_unopenable, mobile_primary_action_unusable,
    # mobile_tap_target_too_small, mobile_blocking_overlay) and stay MEDIUM: a per-name reachability
    # test proved unreliable (it flagged sites whose menu opens fine), so it is a reviewer-facing
    # signal, never a high-confidence datum claim.
    "mobile_horizontal_overflow", "mobile_broken_image", "mobile_broken_css",
    "mobile_broken_javascript", "mobile_broken_font",
})
LOW_CONFIDENCE_ISSUES = frozenset({
    "interface_usable_submission_not_tested", "rendered_only_link_discovered",
    "mobile_page_inconclusive", "origin_domain_migrated",
})
# Dead-page/dead-link issue types the live-nav reachability gate (Gate 2) re-ranks: a 404 is only
# high-confidence visitor-visible when a real click path on the live homepage reaches it.
NAV_GATED_ISSUES = frozenset({"page_http_failure", "dead_link"})
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def is_revenue_path(url: str) -> bool:
    return bool(REVENUE_PATH.search(urlsplit(url).path))


def _bare_host(netloc: str) -> str:
    """www and the bare host are the same site for our purposes."""
    return netloc[4:] if netloc.startswith("www.") else netloc


def confidence_for(issue_type: str) -> str:
    """Rank a finding by verification strength, not by revenue relevance."""
    if issue_type in HIGH_CONFIDENCE_ISSUES or issue_type.startswith("broken_"):
        return "high"
    if issue_type in LOW_CONFIDENCE_ISSUES:
        return "low"
    return "medium"


def enrich_findings(rows: list["ResultRow"]) -> list["ResultRow"]:
    """Assign each row a confidence tier and a revenue-relevance tag before ranking."""
    for row in rows:
        if not row.confidence:
            row.confidence = confidence_for(row.issue_type)
        row.revenue_relevant = is_revenue_path(row.failed_url or row.source_url)
    return rows


def rank_findings(rows: list["ResultRow"]) -> list["ResultRow"]:
    """Verified failures first; within a tier, revenue-relevant ones first."""
    return sorted(rows, key=lambda row: (
        CONFIDENCE_ORDER.get(row.confidence, 3),
        not row.revenue_relevant,
        row.third_party,
        row.issue_type,
        str(row.failed_url),
    ))


@dataclass(slots=True)
class PageRecord:
    url: str
    source_url: str
    depth: int
    reason: str
    status_code: int | str = ""
    final_url: str = ""
    redirect_chain: str = ""
    content_type: str = ""
    body: str = ""
    error: str = ""
    parser: object | None = None


@dataclass(slots=True)
class SkipRecord:
    url: str
    source_url: str
    reason: str


@dataclass(slots=True)
class ResultRow:
    organization: str
    issue_type: str
    source_url: str
    failed_url: str
    status_code: int | str
    evidence: str
    screenshot_path: str = ""
    context: str = "http"
    source: str = "generic_site_check"
    confidence: str = ""
    revenue_relevant: bool = False
    third_party: bool = False


@dataclass(slots=True)
class OpportunityRow:
    organization: str
    source_url: str
    exact_observed_evidence: str
    possible_automation: str
    confidence: str
    question_before_proposing_work: str
    source: str = "automation_opportunity"


@dataclass(slots=True)
class CoverageRow:
    organization: str
    homepage: str
    pages_discovered: int
    pages_visited: int
    visited_urls: str
    pages_skipped: int
    skipped_urls_and_reasons: str
    internal_links_checked: int
    images_assets_checked: int
    desktop_browser_pages: int
    mobile_browser_pages: int
    revenue_controls_checked: int
    forms_inspected: int
    inaccessible_pages: int
    runtime_seconds: float
    coverage_sufficient: bool
    coverage_status: str
    homepage_inspection_completed: bool
    bounded_inventory_completed: bool
    generic_checks_completed: bool
    fast_audit_completed: bool
    deep_revenue_requested: bool
    deep_revenue_completed: bool
    subsystem_errors: str


@dataclass(slots=True)
class OrganizationSummaryRow:
    organization: str
    homepage: str
    high_confidence: int
    medium_confidence: int
    low_confidence: int
    automation_opportunities: int
    scan_outcome: str


def _detach_iframes(page) -> None:
    """Remove iframes before discover_controls iterates page.frames.

    discover_controls loops every frame calling untimed Playwright methods; a busy cross-origin
    embed makes frame.count() block forever (one site carried 21 frames, one wedging the worker
    for ~18 min). Detaching iframes drops them from page.frames. Runs after the
    failed-iframe check, so that detection is unaffected; third-party widgets are not the
    organization's own controls, so nothing actionable is lost.
    """
    try:
        page.evaluate("document.querySelectorAll('iframe').forEach(frame => frame.remove())")
        page.wait_for_timeout(200)
    except Exception:
        pass


def _browser_priority(page: PageRecord) -> tuple[int, int, str]:
    return (0 if page.depth == 0 else 1 if PRIORITY.search(page.url) else 2, page.depth, page.url)


def browser_audit(
    organization: str, homepage: str, pages: list[PageRecord], output_dir: Path, timeout: float,
    deadline: float | None = None,
) -> tuple[list[ResultRow], int, int, int, int, bool, set[str] | None, set[str] | None]:
    """Render a bounded priority subset; inspect interfaces but never submit them.

    Also returns the live homepage's primary-nav and footer link sets (normalized) for Gate 2, or
    (None, None) when the homepage never rendered.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Python Playwright is required for Auditor v2 browser checks") from exc
    confirmed: list[ResultRow] = []; manual: list[ResultRow] = []
    timed_out = False
    controls_checked = forms_inspected = desktop_rendered = mobile_rendered = 0
    desktop_primary: dict[str, list[tuple[str, str, str]]] = {}
    # Desktop baseline for the mobile-only gate: a mobile failure is only additive (not a duplicate
    # of an existing desktop finding) when the same failure did NOT occur at the desktop viewport.
    desktop_overflow: dict[str, int] = {}
    seen_broken_assets: set[str] = set()
    # Gate 2 needs the live homepage's real click paths. None until the homepage renders, so an
    # un-rendered homepage does not read as "no nav" and wrongly clear every dead link.
    primary_nav: set[str] | None = None; secondary_nav: set[str] | None = None
    candidates = sorted([p for p in pages if p.status_code and int(p.status_code) < 400], key=_browser_priority)
    desktop = candidates[:6]
    mobile = ([next((p for p in candidates if p.depth == 0), candidates[0])] if candidates else [])
    mobile += [p for p in candidates if p not in mobile and PRIORITY.search(p.url)][:2]
    screenshot_dir = output_dir / "screenshots" / re.sub(r"[^a-z0-9]+", "-", organization.lower()).strip("-")
    timeout_ms = round(timeout * 1000)
    with sync_playwright() as pw:
        executable = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
        launch = security.browser_launch_kwargs()
        if executable: launch["executable_path"] = executable
        browser = pw.chromium.launch(**launch)
        for page_index, record in enumerate(desktop, 1):
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True; break
            context = browser.new_context(viewport={"width": 1440, "height": 1000})
            page = context.new_page()
            page_timeout = timeout_ms if deadline is None else max(1, min(timeout_ms, round((deadline - time.monotonic()) * 1000)))
            page.set_default_timeout(page_timeout)
            failures: list[str] = []; serious_console: list[str] = []
            bad_responses: list[tuple[str, str, int]] = []
            page.on("requestfailed", lambda req: failures.append(f"{req.url}: {req.failure}"))
            page.on("console", lambda msg: serious_console.append(msg.text) if msg.type == "error" else None)
            # The render downloads every asset; capture failed responses instead of re-fetching them.
            page.on("response", lambda resp: bad_responses.append((resp.url, resp.request.resource_type, resp.status)) if resp.status >= 400 else None)
            try:
                response = page.goto(record.url, wait_until="domcontentloaded", timeout=page_timeout)
                page.wait_for_timeout(700)
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)"); page.wait_for_timeout(500)
                # Desktop horizontal overflow baseline for the mobile-only gate (WCAG 1.4.10 Reflow).
                desktop_overflow[record.url] = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                text = page.locator("body").inner_text(timeout=3000)
                visible = find_visible_error(text) or find_explicit_failure(text, page.url)
                shot = screenshot_dir / f"desktop-{page_index}.png"; shot.parent.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(shot), full_page=False)
                desktop_rendered += 1
                for asset_url, resource_type, resp_status in bad_responses:
                    if resource_type not in {"image", "stylesheet", "script", "font"}:
                        continue
                    # 404/410/5xx only: 401/403 are often hotlink or auth protection that still renders.
                    if not (resp_status in {404, 410} or resp_status >= 500) or asset_url in seen_broken_assets:
                        continue
                    seen_broken_assets.add(asset_url)
                    kind = {"stylesheet": "css", "script": "javascript"}.get(resource_type, resource_type)
                    off_site = _bare_host(urlsplit(asset_url).netloc) != _bare_host(urlsplit(homepage).netloc)
                    manual.append(ResultRow(organization, f"broken_{kind}", record.url, asset_url, resp_status, f"Visible {resource_type} returned HTTP {resp_status} during render", str(shot), "desktop", "generic_site_check", third_party=off_site))
                status = response.status if response else ""
                if visible or isinstance(status, int) and (status in {404, 410} or status >= 500):
                    manual.append(ResultRow(organization,"rendered_page_failure", record.url, page.url, status, visible or f"HTTP {status}", str(shot), "desktop", "generic_site_check"))
                broken_images = page.locator("img:visible").evaluate_all("els => els.filter(e => e.complete && e.naturalWidth === 0).map(e => e.currentSrc || e.src)")
                for image_url in broken_images:
                    manual.append(ResultRow(organization,"rendered_broken_image", record.url, image_url, "", "Visible rendered image finished loading with zero natural dimensions", str(shot), "desktop", "generic_site_check"))
                static_links = set()
                parser = record.parser
                if parser:
                    static_links = {normalize_inventory_url(url) for url, _label in parser.links}
                rendered_links = set(page.locator("a[href]").evaluate_all("els => els.map(e => e.href)"))
                if record.depth == 0:
                    # The live homepage's click paths, after redirects: primary menu vs footer.
                    primary_hrefs = page.locator("header a[href], nav a[href], [role=navigation] a[href]").evaluate_all("els => els.map(e => e.href)")
                    footer_hrefs = page.locator("footer a[href], [role=contentinfo] a[href]").evaluate_all("els => els.map(e => e.href)")
                    primary_nav = {n for href in primary_hrefs if (n := normalize_inventory_url(href))}
                    secondary_nav = {n for href in footer_hrefs if (n := normalize_inventory_url(href))}
                for rendered_url in sorted(rendered_links):
                    normalized = normalize_inventory_url(rendered_url)
                    if normalized and normalized not in static_links and urlsplit(normalized).netloc == _bare_host(urlsplit(homepage).netloc):
                        manual.append(ResultRow(organization,"rendered_only_link_discovered", record.url, normalized, "", "Internal link exists only after JavaScript rendering", str(shot), "desktop", "generic_site_check"))
                frames = page.locator("iframe:visible")
                for idx in range(frames.count()):
                    src = frames.nth(idx).get_attribute("src") or ""
                    if src and any(src in failure for failure in failures):
                        manual.append(ResultRow(organization,"failed_iframe_widget", record.url, src, "", "Visible iframe request failed", str(shot), "desktop", "generic_site_check"))
                _detach_iframes(page)
                state = EcommerceTraversalState()
                controls = filter_ecommerce_controls(discover_controls(page), page.url, state)
                desktop_primary[record.url] = [(control.category, control.name, control.target) for control in controls]
                seen_categories: set[str] = set()
                for control in controls:
                    if control.category in seen_categories: continue
                    seen_categories.add(control.category); controls_checked += 1
                    if control.submit_risk:
                        forms_inspected += 1
                        manual.append(ResultRow(organization,"interface_usable_submission_not_tested", record.url, control.target, "", f"Visible {control.category} form control '{control.name}' inspected without submission", str(shot), "desktop", "generic_site_check"))
                forms = page.locator("form:visible")
                forms_inspected += forms.count()
                for idx in range(forms.count()):
                    form = forms.nth(idx)
                    fields = form.locator("input:not([type=hidden]), textarea, select").count()
                    submits = form.locator("button, input[type=submit]").count()
                    if fields and submits:
                        manual.append(ResultRow(organization,"interface_usable_submission_not_tested", record.url, page.url, "", "Usable visible form interface; submission intentionally not tested", str(shot), "desktop", "generic_site_check"))
                    else:
                        manual.append(ResultRow(organization,"interface_broken", record.url, page.url, "", "Visible form lacks fields or a submission control", str(shot), "desktop", "generic_site_check"))
                if serious_console:
                    manual.append(ResultRow(organization,"serious_console_error", record.url, page.url, "", serious_console[0][:500], str(shot), "desktop", "generic_site_check"))
            except Exception as exc:
                confirmed.append(ResultRow(organization,"browser_page_unreachable", record.url, record.url, "", str(exc).splitlines()[0], context="desktop", source="generic_site_check"))
            context.close()
        # Freeze the desktop broken-asset set as the baseline: an asset that already failed at
        # desktop is not a mobile-only failure, so the mobile pass only flags NEW breakage.
        desktop_broken_assets = set(seen_broken_assets)
        for page_index, record in enumerate(mobile[:3], 1):
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True; break
            context = browser.new_context(viewport={"width": MOBILE_VIEWPORT["width"], "height": MOBILE_VIEWPORT["height"]}, is_mobile=True, has_touch=True)
            page = context.new_page()
            page_timeout = timeout_ms if deadline is None else max(1, min(timeout_ms, round((deadline - time.monotonic()) * 1000)))
            page.set_default_timeout(page_timeout)
            bad_responses: list[tuple[str, str, int]] = []
            page.on("response", lambda resp: bad_responses.append((resp.url, resp.request.resource_type, resp.status)) if resp.status >= 400 else None)
            try:
                page.goto(record.url, wait_until="domcontentloaded", timeout=page_timeout); page.wait_for_timeout(700)
                shot = screenshot_dir / f"mobile-{page_index}.png"; shot.parent.mkdir(parents=True, exist_ok=True); page.screenshot(path=str(shot), full_page=False)
                mobile_rendered += 1
                # Mobile-only broken assets: a mobile <picture>/srcset source that 404s only at the
                # phone breakpoint. Truthful "mobile-only" requires the SAME page to have rendered at
                # desktop without the failure - otherwise an asset that 404s at every viewport, on a
                # page the desktop pass simply did not select, reads as a false mobile-only. So gate on
                # the page being in the desktop baseline (desktop_overflow is keyed by desktop-rendered
                # URL) and dedupe against the desktop broken-asset set.
                page_rendered_at_desktop = record.url in desktop_overflow
                mobile_seen_assets: set[str] = set()
                for asset_url, resource_type, resp_status in (bad_responses if page_rendered_at_desktop else []):
                    if resource_type not in {"image", "stylesheet", "script", "font"}:
                        continue
                    if not (resp_status in {404, 410} or resp_status >= 500):
                        continue
                    if asset_url in desktop_broken_assets or asset_url in mobile_seen_assets:
                        continue
                    mobile_seen_assets.add(asset_url)
                    kind = {"stylesheet": "css", "script": "javascript"}.get(resource_type, resource_type)
                    off_site = _bare_host(urlsplit(asset_url).netloc) != _bare_host(urlsplit(homepage).netloc)
                    manual.append(ResultRow(organization, f"mobile_broken_{kind}", record.url, asset_url, resp_status, f"Visible {resource_type} returned HTTP {resp_status} at the mobile breakpoint but not at desktop", str(shot), "mobile", "mobile_check", confidence="high", third_party=off_site))
                # Mobile-only horizontal overflow (WCAG 1.4.10 Reflow). High only when the desktop
                # render was measured and did NOT overflow, so it is genuinely mobile-specific.
                overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                if overflow > 80:
                    desktop_over = desktop_overflow.get(record.url)
                    note = ("Content is wider than the phone viewport, forcing horizontal scroll "
                            "(WCAG 1.4.10 Reflow). A data table, map, or diagram can be an intended "
                            "exception - a reviewer confirms the cause.")
                    if desktop_over is not None and desktop_over <= 80:
                        manual.append(ResultRow(organization,"mobile_horizontal_overflow", record.url, page.url, "", f"Mobile-only horizontal overflow: {overflow}px at 390px wide, no overflow at desktop. {note}", str(shot), "mobile", "mobile_check", confidence="high"))
                    elif desktop_over is None:
                        manual.append(ResultRow(organization,"mobile_horizontal_overflow", record.url, page.url, "", f"Horizontal overflow: {overflow}px at 390px wide; desktop overflow not measured for this page, so mobile-only status is unconfirmed. {note}", str(shot), "mobile", "mobile_check", confidence="medium"))
                    # desktop also overflowed -> not mobile-only -> suppressed (out of this task's scope).
                overlays = page.locator('[role=dialog]:visible, .modal:visible, .overlay:visible')
                if overlays.count() and overlays.first.bounding_box() and overlays.first.bounding_box()["height"] > 650:
                    manual.append(ResultRow(organization,"mobile_blocking_overlay", record.url, page.url, "", "Large visible overlay blocks the mobile viewport", str(shot), "mobile", "mobile_check", confidence="medium"))
                # Mobile navigation reachability, tested by the MENU MECHANISM, not by re-matching
                # each desktop control by name. Per-name matching was unreliable: a control whose
                # discovered "name" is a logo filename, an ARIA label, or a run of body text can never
                # be re-found as visible text at mobile, so it read as "unreachable" even on sites
                # whose menu works fine (live-verified on real sites that open normally yet were
                # flagged). Instead, count visible in-viewport nav links and
                # confirm the hamburger reveals them. Emits at most one MEDIUM finding per page - a
                # collapsed mobile menu is a real signal, but headless click reliability is imperfect,
                # so it is a reviewer-facing medium, never a high-confidence datum claim.
                def _nav_links_visible() -> int:
                    return int(page.evaluate(
                        "() => [...document.querySelectorAll('header a, nav a, [role=navigation] a')]"
                        ".filter(a => { const r = a.getBoundingClientRect();"
                        f" return r.width>0 && r.height>0 && r.right>0 && r.left<{MOBILE_VIEWPORT['width']}; }}).length"
                    ))
                menu_toggle = page.locator(
                    'button[aria-label*="menu" i], [role=button][aria-label*="menu" i], '
                    'button[aria-label*="navigation" i], [role=button][aria-label*="navigation" i], '
                    '[aria-controls][aria-expanded], [data-testid*="menu" i], [class*="hamburger" i], '
                    'button:has-text("Menu")'
                ).first
                has_mobile_menu = menu_toggle.count() > 0
                primary = desktop_primary.get(record.url, [])
                controls_checked += len(primary)
                has_primary_nav = bool(primary)
                nav_before = _nav_links_visible()
                # Nav already substantially visible in the viewport => a visitor can navigate.
                menu_opened = nav_before >= 3
                if has_mobile_menu and not menu_opened:
                    expanded_before = menu_toggle.get_attribute("aria-expanded")
                    try:
                        # A menu toggle reveals navigation; it is not a form submission, so clicking it
                        # to test whether it opens is safe.
                        menu_toggle.click(timeout=2000); page.wait_for_timeout(800)
                        expanded_after = menu_toggle.get_attribute("aria-expanded")
                        menu_opened = (_nav_links_visible() > nav_before
                                       or (expanded_after == "true" and expanded_before != "true"))
                    except Exception:
                        menu_opened = False  # a toggle a visitor cannot even click is not opening
                if has_primary_nav and not menu_opened:
                    if has_mobile_menu:
                        manual.append(ResultRow(organization,"mobile_nav_unopenable", record.url, record.url, "", "The mobile menu button does not reveal the site navigation when tapped (nav stays collapsed and aria-expanded does not open), so the primary actions behind it are unreachable on a phone", str(shot), "mobile", "mobile_check", confidence="medium"))
                    elif nav_before == 0:
                        manual.append(ResultRow(organization,"mobile_primary_action_unusable", record.url, record.url, "", "Desktop primary navigation is not visible at the mobile viewport and there is no menu control to reveal it", str(shot), "mobile", "mobile_check", confidence="medium"))
                # Genuinely tiny tap targets (WCAG 2.2 SC 2.5.8: 24x24 CSS px minimum). Require BOTH
                # dimensions under 24 so wide-but-short inline text links (exempt under the criterion's
                # inline exception) are not flagged; skip non-label control names (logo files, prose).
                for category, name, target in primary:
                    if not name or len(name) > 40 or re.search(r"\.(?:png|jpe?g|svg|gif|webp)$", name, re.I):
                        continue
                    loc = page.get_by_text(name, exact=True).first
                    if not loc.count():
                        continue
                    try:
                        if not loc.is_visible():
                            continue
                        box = loc.bounding_box()
                    except Exception:
                        continue
                    if box and box["width"] < 24 and box["height"] < 24:
                        manual.append(ResultRow(organization,"mobile_tap_target_too_small", record.url, target, "", f"Primary {category} tap target '{name}' is {round(box['width'])}x{round(box['height'])} CSS px, below the 24x24 WCAG 2.2 SC 2.5.8 minimum", str(shot), "mobile", "mobile_check", confidence="medium"))
            except Exception as exc:
                manual.append(ResultRow(organization,"mobile_page_inconclusive", record.url, record.url, "", str(exc).splitlines()[0], context="mobile", source="mobile_check"))
            context.close()
        browser.close()
    return confirmed + manual, desktop_rendered, mobile_rendered, controls_checked, forms_inspected, timed_out, primary_nav, secondary_nav


class InventoryParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[tuple[str, str]] = []
        self.assets: list[tuple[str, str]] = []
        self.text: list[str] = []
        self._nonvisible_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "template", "noscript"}:
            self._nonvisible_depth += 1
        values = dict(attrs)
        if tag == "a" and values.get("href"):
            self.links.append((urljoin(self.base_url, values["href"] or ""), values.get("aria-label") or values.get("title") or ""))
        if tag == "img" and values.get("src"):
            asset = public_asset_url(self.base_url, values["src"] or "")
            if asset: self.assets.append((asset, "image"))
        if tag == "script" and values.get("src"):
            asset = public_asset_url(self.base_url, values["src"] or "")
            if asset: self.assets.append((asset, "javascript"))
        if tag == "link" and values.get("href"):
            rel = (values.get("rel") or "").lower()
            href = values["href"] or ""
            kind = "css" if "stylesheet" in rel else "font" if "preload" in rel and (values.get("as") or "") == "font" else "document" if DOCUMENT_EXT.search(href) else ""
            if kind:
                asset = public_asset_url(self.base_url, href)
                if asset: self.assets.append((asset, kind))
        style = values.get("style") or ""
        for match in CSS_URL.finditer(style):
            asset = public_asset_url(self.base_url, match.group(1))
            if asset: self.assets.append((asset, "css_background_image"))

    def handle_data(self, data: str) -> None:
        if not self._nonvisible_depth and data.strip():
            self.text.append(data.strip())

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "template", "noscript"} and self._nonvisible_depth:
            self._nonvisible_depth -= 1


def public_asset_url(base_url: str, reference: str) -> str:
    reference = reference.strip()
    if not reference or unquote(reference).lstrip("\\").startswith("#"):
        return ""
    parsed = urlsplit(reference)
    if parsed.scheme.lower() in {"data", "blob", "about", "javascript", "mailto", "tel"}:
        return ""
    absolute = urljoin(base_url, reference)
    if urlsplit(absolute).scheme.lower() not in {"http", "https"}:
        return ""
    return quote(absolute, safe=":/?#[]@!$&'()*+,;=%")


def normalize_inventory_url(url: str) -> str:
    normalized = normalize_destination(url)
    if not normalized or INVALID_URL_CHARS.search(normalized):
        return ""
    parsed = urlsplit(normalized)
    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower().startswith("utm_") or key.lower() in TRACKING_KEYS:
            continue
        query.append((key, value))
    # Canonicalize www to the bare host so the crawl treats them as one site: otherwise a site
    # whose links use www (or vice versa) has its internal pages skipped as different_origin and
    # is only homepage-crawled (a common real-site pattern).
    return urlunsplit((parsed.scheme, _bare_host(parsed.netloc), parsed.path, urlencode(sorted(query)), ""))


def url_kind(url: str) -> str:
    path = urlsplit(url).path
    if re.search(r"/(?:checkout)(?:/|$)", path, re.I): return "checkout"
    if re.search(r"/(?:cart|basket)(?:/|$)", path, re.I): return "cart"
    if PRODUCT.search(path): return "product"
    if LISTING.search(path): return "listing"
    if CALENDAR.search(path): return "calendar"
    return "page"


def skip_reason(url: str, origin: str, budgets: dict[str, str]) -> str:
    normalized = normalize_inventory_url(url)
    if not normalized: return "unsupported_or_invalid_url"
    parsed = urlsplit(normalized)
    if parsed.netloc != urlsplit(origin).netloc: return "different_origin"
    if any(REJECT_QUERY.match(k) for k, _ in parse_qsl(parsed.query)): return "pagination_sort_filter_search_or_calendar_variant"
    if re.search(r"/(?:page/\d+|search)(?:/|$)", parsed.path, re.I): return "pagination_or_search_result"
    kind = url_kind(normalized)
    if kind in budgets and budgets[kind] and budgets[kind] != normalized: return f"organization_{kind}_limit"
    return ""


def priority_score(url: str, label: str = "") -> int:
    path = urlsplit(url).path.strip("/").lower()
    # Shallow visitor-action pages outrank keyword-bearing archives and posts.
    if path and path.count("/") <= 1 and PRIORITY.search(f"{path} {label}"):
        return 0
    return 1 if PRIORITY.search(f"{url} {label}") else 2


def _fetch_asset(url: str, timeout: float = 15) -> tuple[int | str, str, str]:
    # Browser UA (not a bot UA): a dead link is only a finding if a real visitor hits it, and a bot
    # UA gets 403-walled on sites that serve fine to a browser, manufacturing false dead links.
    try:
        request = UrlRequest(url, headers={"User-Agent": BROWSER_UA})
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.geturl(), response.headers.get("Content-Type", "")
    except HTTPError as exc:
        return exc.code, exc.geturl(), exc.headers.get("Content-Type", "")
    except (URLError, TimeoutError, OSError, ValueError, InvalidURL) as exc:
        # InvalidURL/ValueError = a malformed href (spaces, control chars) that slipped through; a
        # single bad link must read as unreachable, never abort the org (isolate per-link failures).
        return "", url, str(exc)


def _variant_is_ok(url: str, timeout: float = 5) -> bool:
    """True when the trailing-slash sibling of a 404'd URL actually serves a visitor HTTP 200.

    normalize_inventory_url strips the trailing slash (and www), so the crawl fetches
    `example.org/special-events` (404) for a nav that links `www.example.org/special-events/`
    (200). That 404 is canonicalization noise, not a dead nav target. Follow redirects: a visitor who
    clicks the slashed nav link lands on a 200 even when the bare host 301s to www first.
    """
    parsed = urlsplit(url)
    if not parsed.path or parsed.path == "/" or parsed.path.endswith("/"):
        return False
    variant = urlunsplit((parsed.scheme, parsed.netloc, parsed.path + "/", parsed.query, ""))
    status, _final, _content_type = _fetch_asset(variant, timeout)
    return status == 200


def resolve_canonical_homepage(
    homepage: str, timeout: float = 15, deadline: float | None = None,
) -> tuple[str, str]:
    """Follow the homepage's redirects; return (canonical_homepage, migrated_from_host).

    Gate 1: when the homepage 3xx-forwards to a DIFFERENT host, the origin domain is abandoned and
    the destination is the org's real site. Return the destination as canonical so the crawl scans
    it, and the old bare host so its stale findings can be dropped. www and the bare host are the
    same site, so a plain www redirect is not a migration. migrated_from is "" when not migrated.
    """
    requested = normalize_inventory_url(homepage) or homepage
    if deadline is not None and time.monotonic() >= deadline:
        return requested, ""
    status, final, _content_type = _fetch_asset(homepage, min(timeout, 10))
    if not isinstance(status, int) or not final:
        return requested, ""
    origin_host = _bare_host(urlsplit(requested).netloc)
    final_host = _bare_host(urlsplit(final).netloc)
    if origin_host and final_host and origin_host != final_host:
        return normalize_inventory_url(final) or final, origin_host
    return requested, ""


def migration_finding(organization: str, homepage: str, canonical: str) -> ResultRow:
    """The single Gate-1 finding: origin domain migrated; its legacy failures are not the org's."""
    return ResultRow(
        organization, "origin_domain_migrated", homepage, homepage, "",
        f"Homepage redirects off {_bare_host(urlsplit(homepage).netloc)} to {canonical}; the origin "
        "domain is abandoned. Its internal pages are a legacy site, not the org's current site, so "
        "their failures are not visitor-visible on the live site. Only actionable if the org still "
        "controls the old domain and stale bookmarks or links point at its dead legacy paths.",
        confidence="low",
    )


def suppress_origin_findings(rows: list[ResultRow], migrated_from: str) -> list[ResultRow]:
    """Drop findings that live on the abandoned origin host after a Gate-1 migration."""
    if not migrated_from:
        return rows
    kept: list[ResultRow] = []
    for row in rows:
        host = _bare_host(urlsplit(row.failed_url or row.source_url).netloc)
        if host == migrated_from:
            continue
        kept.append(row)
    return kept


def apply_nav_reachability_gate(
    rows: list[ResultRow], primary_nav: set[str] | None, secondary_nav: set[str] | None,
    timeout: float = 5, deadline: float | None = None,
) -> None:
    """Gate 2: rank dead pages/links by whether the live rendered homepage nav actually reaches them.

    high only when the primary nav/menu of the live homepage (after redirects) links it; footer-only
    reachability is lower value; a target present only in stale body text or an old sitemap, or a
    trailing-slash/URL variant the nav does not use, is downgraded. Mutates rows in place. Skips
    entirely when the homepage was not rendered (nav is None), so an un-rendered site is not falsely
    cleared, which removes a class of false positives on sites whose nav renders fine.
    """
    if primary_nav is None and secondary_nav is None:
        return
    primary = primary_nav or set()
    secondary = secondary_nav or set()
    for row in rows:
        if row.issue_type not in NAV_GATED_ISSUES:
            continue
        normalized = normalize_inventory_url(row.failed_url)
        past_deadline = deadline is not None and time.monotonic() >= deadline
        if not past_deadline and _variant_is_ok(row.failed_url, timeout):
            row.confidence = "low"
            row.evidence += (" | trailing-slash/URL variant: the slashed form returns HTTP 200, so "
                             "this is canonicalization noise, not a dead nav target")
        elif normalized in primary:
            row.confidence = "high"
        elif normalized in secondary:
            row.confidence = "medium"
            row.evidence += " | reachable only from footer navigation, not the primary menu"
        else:
            row.confidence = "low"
            row.evidence += (" | not present in the live rendered homepage navigation (stale body "
                             "text, old sitemap, or a removed link), so not a current visitor click path")


async def crawl_inventory(homepage: str, timeout: float = 20, deadline: float | None = None,
                          max_pages: int = MAX_PAGES, max_depth: int = MAX_DEPTH) -> tuple[list[PageRecord], list[SkipRecord], int, int]:
    from crawlee import ConcurrencySettings, Request
    from crawlee.configuration import Configuration
    from crawlee.crawlers import HttpCrawler, HttpCrawlingContext
    from crawlee.http_clients import ImpitHttpClient

    origin = normalize_inventory_url(homepage)
    pages: list[PageRecord] = []
    skips: list[SkipRecord] = []
    known: set[str] = {origin}
    budgets = {key: "" for key in ("listing", "product", "cart", "checkout", "calendar")}
    sitemap_urls: list[str] = []
    try:
        sitemap_url = urljoin(origin, "/sitemap.xml")
        sitemap_body = await asyncio.to_thread(lambda: urlopen(UrlRequest(sitemap_url, headers={"User-Agent": "AuditorV2/2.0"}), timeout=timeout).read().decode("utf-8", "replace"))
        sitemap_urls = [normalize_inventory_url(value.strip()) for value in re.findall(r"<loc>(.*?)</loc>", sitemap_body, re.I | re.S)]
        # Expand a bounded sitemap index instead of crawling XML as visitor pages.
        child_maps = [url for url in sitemap_urls if urlsplit(url).path.lower().endswith(".xml")][:8]
        if child_maps:
            sitemap_urls = []
            for child in child_maps:
                child_body = await asyncio.to_thread(lambda child=child: urlopen(UrlRequest(child, headers={"User-Agent": "AuditorV2/2.0"}), timeout=min(timeout, 8)).read().decode("utf-8", "replace"))
                sitemap_urls.extend(normalize_inventory_url(value.strip()) for value in re.findall(r"<loc>(.*?)</loc>", child_body, re.I | re.S))
        sitemap_urls = [url for url in sitemap_urls if url and not skip_reason(url, origin, budgets)]
    except Exception:
        sitemap_urls = []
    links_checked = 0
    assets_checked = 0
    storage = TemporaryDirectory(prefix="auditor-v2-crawlee-")
    # Impersonate Chrome for the main crawl. Crawlee's default (Firefox impersonation) still gets
    # 403-walled by UA/fingerprint filters on sites that serve fine to a real Chrome, so a homepage
    # a visitor loads normally comes back empty and the org is scored insufficient_coverage. This
    # mirrors why the accuracy gates already fetch reachability under BROWSER_UA (a Chrome UA).
    crawler = HttpCrawler(
        http_client=ImpitHttpClient(browser="chrome"),
        configuration=Configuration(storage_dir=storage.name, purge_on_start=True, log_level="ERROR"),
        max_requests_per_crawl=max_pages, max_crawl_depth=max_depth,
        max_request_retries=0, use_session_pool=False,
        # Bound each page fetch+handler so one slow/large page cannot wedge the crawl past the org
        # budget (one site ran ~27 min under a 150s budget on a single stuck request).
        request_handler_timeout=timedelta(seconds=max(timeout, 30)),
        ignore_http_error_status_codes=range(400, 600),
        concurrency_settings=ConcurrencySettings(min_concurrency=1, max_concurrency=1, desired_concurrency=1),
    )

    @crawler.router.default_handler
    async def handler(context: HttpCrawlingContext) -> None:
        nonlocal links_checked, assets_checked
        if deadline is not None and time.monotonic() >= deadline:
            skips.append(SkipRecord(context.request.url, str((context.request.user_data or {}).get("source", "")), "organization_timeout"))
            return
        data = context.request.user_data or {}
        response = context.http_response
        raw = await response.read()
        body = raw.decode("utf-8", errors="replace")
        status = int(getattr(response, "status_code", 0) or 0)
        final_url = str(getattr(response, "url", context.request.url))
        record = PageRecord(context.request.url, str(data.get("source", "")), int(data.get("depth", 0)), str(data.get("reason", "navigation")), status, final_url, f"{context.request.url} -> {final_url}" if final_url != context.request.url else context.request.url, str(getattr(response, "headers", {}).get("content-type", "")), body)
        pages.append(record)
        if status >= 400 or "html" not in record.content_type.lower(): return
        parser = InventoryParser(final_url)
        parser.feed(body)
        # Asset reachability is detected during the browser render (page.on "response"), not by a
        # separate serial HTTP pass, so a deep crawl no longer spends its time budget re-fetching
        # every image/css/js. Here we only record how many distinct assets the page carries.
        assets_checked += len(dict.fromkeys(parser.assets))
        record.parser = parser
        if int(data.get("depth", 0)) >= max_depth: return
        candidates = sorted(parser.links, key=lambda item: (priority_score(*item), normalize_inventory_url(item[0])))
        for target, label in candidates:
            links_checked += 1
            normalized = normalize_inventory_url(target)
            reason = skip_reason(normalized, origin, budgets)
            if normalized in known: reason = reason or "duplicate_normalized_url"
            if len(known) >= max_pages: reason = reason or "page_cap"
            if reason:
                skips.append(SkipRecord(normalized or target, final_url, reason)); continue
            known.add(normalized)
            kind = url_kind(normalized)
            if kind in budgets and not budgets[kind]: budgets[kind] = normalized
            await crawler.add_requests([Request.from_url(normalized, user_data={"source": final_url, "depth": int(data.get("depth", 0)) + 1, "reason": "priority_navigation" if priority_score(normalized, label) == 0 else "navigation"})])

    @crawler.failed_request_handler
    async def failed(context, error: Exception) -> None:
        data = context.request.user_data or {}
        pages.append(PageRecord(context.request.url, str(data.get("source", "")), int(data.get("depth", 0)), str(data.get("reason", "navigation")), error=str(error)))

    seeds = [Request.from_url(origin, user_data={"source": "", "depth": 0, "reason": "homepage"})]
    for sitemap_url in sorted(sitemap_urls, key=lambda url: (priority_score(url), url)):
        # Leave queue capacity for priority navigation discovered from the homepage.
        if len(seeds) >= 4: break
        if sitemap_url in known: continue
        reason = skip_reason(sitemap_url, origin, budgets)
        if reason:
            skips.append(SkipRecord(sitemap_url, urljoin(origin, "/sitemap.xml"), reason)); continue
        known.add(sitemap_url)
        kind = url_kind(sitemap_url)
        if kind in budgets and not budgets[kind]: budgets[kind] = sitemap_url
        seeds.append(Request.from_url(sitemap_url, user_data={"source": urljoin(origin, "/sitemap.xml"), "depth": 1, "reason": "sitemap"}))
    await crawler.run(seeds)
    storage.cleanup()
    return pages, skips, links_checked, assets_checked


def classify_http_results(organization: str, pages: list[PageRecord]) -> tuple[list[ResultRow], list[OpportunityRow]]:
    rows: list[ResultRow] = []
    opportunities: list[OpportunityRow] = []
    for page in pages:
        if page.error:
            issue = "ssl_certificate_failure" if SSL_ERROR.search(page.error) else "page_navigation_failure"
            rows.append(ResultRow(organization, issue, page.source_url or page.url, page.url, "", page.error))
            continue
        if isinstance(page.status_code, int) and (page.status_code in {404, 410} or page.status_code >= 500):
            rows.append(ResultRow(organization, "page_http_failure", page.source_url or page.url, page.url, page.status_code, f"Visitor page returned HTTP {page.status_code}"))
        parser = page.parser
        if parser is None and page.body:
            parser = InventoryParser(page.final_url or page.url)
            parser.feed(page.body)
        if parser:
            visible_text = " ".join(parser.text)
            visible = find_visible_error(visible_text) or find_explicit_failure(visible_text, page.final_url)
            if visible:
                rows.append(ResultRow(organization, "visible_site_failure", page.url, page.final_url, page.status_code, visible))
            text = " ".join(parser.text)
            for pattern, automation in OPPORTUNITY_PATTERNS:
                match = pattern.search(text)
                if match:
                    evidence = text[max(0, match.start()-80):match.end()+120]
                    opportunities.append(OpportunityRow(organization, page.url, evidence, automation, "medium", "How is this public instruction handled today, and where does staff intervention occur?"))
    return rows, opportunities


def check_homepage_links(
    organization: str, pages: list[PageRecord], timeout: float = 10, deadline: float | None = None,
) -> list[ResultRow]:
    """Reachability-check same-site homepage links the bounded crawl never fetched.

    The crawl only verifies pages it selects under its page cap and priority ranking, so a dead
    homepage link to a non-selected page is otherwise missed (a real recall gap: a site
    linked 'Support Us' -> support-us.html, a 404, while the crawl fetched donatesupport.html).
    """
    home = next((page for page in pages if page.depth == 0 and page.parser), None)
    if home is None:
        return []
    crawled = {normalize_inventory_url(page.final_url or page.url) for page in pages}
    origin = _bare_host(urlsplit(home.final_url or home.url).netloc)
    rows: list[ResultRow] = []
    seen: set[str] = set()
    for target, _label in home.parser.links:
        if deadline is not None and time.monotonic() >= deadline:
            break
        normalized = normalize_inventory_url(target)
        if not normalized or normalized in crawled or normalized in seen:
            continue
        parsed = urlsplit(normalized)
        # Treat www and the bare host as the same site (the crawl fetched only one of them).
        if _bare_host(parsed.netloc) != origin or ASSET_EXT.search(parsed.path):
            continue
        seen.add(normalized)
        if len(seen) > 30:
            break
        status, _final, _content_type = _fetch_asset(normalized, min(timeout, 5))
        if isinstance(status, int) and (status in {404, 410} or status >= 500):
            rows.append(ResultRow(organization, "dead_link", home.url, normalized, status,
                                  f"Homepage link to a page that returned HTTP {status}"))
    return rows


def _write(path: Path, rows: list[object], row_type: type) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row_type.__dataclass_fields__))
        writer.writeheader(); writer.writerows(asdict(row) for row in rows)


def deduplicate_results(rows: list[ResultRow]) -> list[ResultRow]:
    """Merge only identical finding identities, retaining corroborating evidence."""
    merged: dict[tuple[str, str, str, str], ResultRow] = {}
    for row in rows:
        key = (row.organization, row.source_url, row.failed_url, row.issue_type)
        existing = merged.get(key)
        if existing is None:
            merged[key] = row
            continue
        if row.evidence and row.evidence not in existing.evidence:
            existing.evidence = f"{existing.evidence} | {row.evidence}"
        if not existing.screenshot_path and row.screenshot_path:
            existing.screenshot_path = row.screenshot_path
    return list(merged.values())


def _revenue_results(organization: str, evidence_rows) -> list[ResultRow]:
    rows: list[ResultRow] = []
    for row in evidence_rows:
        if row.verification_result == "appears_functional":
            continue
        rows.append(ResultRow(
            organization=organization,
            issue_type=f"revenue_path_{row.category}_{row.interaction_result}",
            source_url=row.source_page,
            failed_url=row.resulting_url or row.original_target,
            status_code=row.main_document_status,
            evidence=row.evidence,
            screenshot_path=row.screenshot_path,
            context="revenue",
            source="revenue_path_verifier",
            confidence="high" if row.verification_result == "confirmed_broken" else "medium",
        ))
    return rows


def _run_stable_revenue_verifier(
    organization: str, homepage: str, revenue_dir: Path, timeout: float,
    deadline: float,
) -> list[BrowserEvidence]:
    """Run the stable verifier as-is behind a v2 process deadline."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("organization deadline reached before revenue verification")
    with TemporaryDirectory(prefix="auditor-v2-revenue-") as directory:
        input_path = Path(directory) / "organization.csv"
        with input_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle); writer.writerow(("organization", "url")); writer.writerow((organization, homepage))
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        subprocess.run(
            [sys.executable, "-m", "auditor", "browser-verify", str(input_path),
             "--output-dir", str(revenue_dir), "--timeout", str(timeout)],
            check=True, timeout=remaining, env=env,
        )
    evidence_path = revenue_dir / "browser-evidence.csv"
    if not evidence_path.exists():
        raise RuntimeError("stable revenue verifier produced no evidence CSV")
    with evidence_path.open(encoding="utf-8", newline="") as handle:
        return [BrowserEvidence(**row) for row in csv.DictReader(handle)]


def _coverage_status(
    pages: list[PageRecord], desktop_count: int, mobile_count: int, fast_complete: bool,
    bounded_complete: bool, generic_complete: bool, subsystem_errors: list[str],
    timed_out: bool = False,
) -> tuple[bool, str, bool]:
    homepage_complete = any(page.depth == 0 and bool(page.status_code) and not page.error for page in pages)
    # A bounded crawl visits what it selects; links skipped for cause (external, duplicate,
    # pagination, budget) are not unvisited coverage, and a small site can be complete at one
    # page. The homepage load plus the rendered desktop and mobile passes establish inspection,
    # whatever the page count; requiring a fixed page floor wrongly failed small sites.
    sufficient = all((
        homepage_complete, bounded_complete, generic_complete,
        desktop_count >= 1, mobile_count >= 1, fast_complete,
        not subsystem_errors,
    ))
    if sufficient:
        return True, "coverage_sufficient", homepage_complete
    # Salvage: the per-org time budget was hit mid-scan. As long as the homepage was inspected, emit
    # the partial coverage already gathered marked partial, rather than discarding it as an empty
    # scan. A slow or hung page must not zero out an org whose homepage (and often much more) was
    # covered; those partial findings are still real. Only a run that never even loaded the homepage
    # (or a non-timeout subsystem failure) reads as insufficient_coverage.
    if timed_out and homepage_complete:
        return False, "partial_coverage", homepage_complete
    return False, "insufficient_coverage", homepage_complete


def _write_outputs(
    output_dir: Path, findings: list[ResultRow],
    opportunities: list[OpportunityRow], coverage: list[CoverageRow],
    summaries: list[OrganizationSummaryRow],
) -> None:
    _write(output_dir / "findings.csv", findings, ResultRow)
    _write(output_dir / "automation-opportunities.csv", opportunities, OpportunityRow)
    _write(output_dir / "coverage.csv", coverage, CoverageRow)
    _write(output_dir / "organization-summary.csv", summaries, OrganizationSummaryRow)


# Cooperative deadline checked between steps: each subsystem gets `deadline` and returns whatever it
# has gathered when the budget is spent. The browser stage renders up to nine pages (~45s solo);
# under parallel workers Chrome instances contend for CPU and roughly double that, so the per-org
# budget must clear ~90s of browser work.
ORG_DEADLINE_SECONDS = 150
# Grace added to the cooperative deadline before the hard backstop force-kills a phase, so the
# cooperative checks get a chance to return partial results first.
HARD_DEADLINE_GRACE = 20
# Empty browser result (rows, desktop, mobile, controls, forms, timed_out, primary_nav, secondary_nav).
_EMPTY_BROWSER_RESULT = ([], 0, 0, 0, 0, True, None, None)


def _bounded_browser_audit(
    organization: str, homepage: str, pages: list[PageRecord], output_dir: Path,
    timeout: float, deadline: float,
):
    """Run browser_audit in a forked child that is force-killed if it overruns the org budget.

    The sync Playwright render can wedge on a single call (a busy cross-origin embed hung
    one site for ~27 min under a 150s budget), and the cooperative deadline is only checked
    between pages. SIGALRM does not reliably interrupt the greenlet-based sync driver, so isolate the
    render in a child process instead: fork inherits the crawled pages in memory (no pickling in),
    only the picklable result comes back over a queue, and a wedged child is terminated/killed. When
    that happens the browser stage returns empty+timed_out and the org salvages its crawl coverage as
    partial. Falls back to running in-process where fork is unavailable (e.g. the test ThreadPool).
    """
    import multiprocessing as mp
    import queue as queue_mod

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _EMPTY_BROWSER_RESULT
    # Forking is only safe from a process's main thread (which is where each ProcessPoolExecutor
    # worker runs an org). Under the test ThreadPool the org runs off the main thread, so run the
    # render in-process there and let the cooperative deadline govern.
    if threading.current_thread() is not threading.main_thread():
        return browser_audit(organization, homepage, pages, output_dir, timeout, deadline)
    try:
        ctx = mp.get_context("fork")
    except ValueError:
        return browser_audit(organization, homepage, pages, output_dir, timeout, deadline)

    result_queue: mp.Queue = ctx.Queue()

    def _worker() -> None:
        try:
            result_queue.put(("ok", browser_audit(organization, homepage, pages, output_dir, timeout, deadline)))
        except Exception as exc:  # relayed to the parent so the fast-audit handler records it
            result_queue.put(("err", f"{exc.__class__.__name__}: {(str(exc).splitlines() or [''])[0]}"))

    proc = ctx.Process(target=_worker, daemon=True)
    proc.start()
    tag = "timeout"; payload = None
    try:
        tag, payload = result_queue.get(timeout=remaining + HARD_DEADLINE_GRACE)
    except queue_mod.Empty:
        pass
    finally:
        proc.join(5)
        if proc.is_alive():
            proc.terminate(); proc.join(5)
        if proc.is_alive():
            proc.kill(); proc.join(5)
    if tag == "ok":
        return payload
    if tag == "err":
        raise RuntimeError(f"browser_audit: {payload}")
    return _EMPTY_BROWSER_RESULT


def _audit_organization(
    index: int, organization: str, homepage: str, input_path: Path,
    output_dir: Path, timeout: float, deep_revenue: bool, collect_html: bool = False,
    max_pages: int = MAX_PAGES, max_depth: int = MAX_DEPTH,
) -> tuple:
    started = time.monotonic(); deadline = started + ORG_DEADLINE_SECONDS; subsystem_errors: list[str] = []
    bounded_complete = generic_complete = fast_complete = deep_complete = timed_out = False
    pages: list[PageRecord] = []; skips: list[SkipRecord] = []
    links = assets = desktop_count = mobile_count = controls_count = forms_count = 0
    rows: list[ResultRow] = []; opportunities: list[OpportunityRow] = []
    primary_nav: set[str] | None = None; secondary_nav: set[str] | None = None
    canonical = homepage; migrated_from = ""
    print(f"[{index}] {organization}: fast bounded inventory", flush=True)
    try:
        # Gate 1: follow the homepage's redirects first. A cross-host 3xx means the origin domain is
        # abandoned; crawl the destination as canonical, not the dead legacy site.
        canonical, migrated_from = resolve_canonical_homepage(homepage, timeout, deadline)
        # asyncio.wait_for is the hard net around the crawl: crawl_inventory returns its partial pages
        # cooperatively by `deadline`, but wait_for cancels a genuinely stuck event loop past it.
        async def _run_crawl():
            return await asyncio.wait_for(
                crawl_inventory(canonical, timeout, deadline, max_pages, max_depth),
                timeout=max(1.0, deadline - time.monotonic() + HARD_DEADLINE_GRACE),
            )
        try:
            pages, skips, links, assets = asyncio.run(_run_crawl())
        except (asyncio.TimeoutError, TimeoutError):
            timed_out = True
        bounded_complete = time.monotonic() < deadline
        if not bounded_complete: timed_out = True
        http_rows, opportunities = classify_http_results(organization, pages)
        rows += http_rows
        rows += check_homepage_links(organization, pages, timeout, deadline)
        if time.monotonic() < deadline:
            # Isolate the browser render in a force-killable child so a wedged Playwright call cannot
            # hang the worker past the budget (see _bounded_browser_audit).
            browser_rows, desktop_count, mobile_count, controls_count, forms_count, browser_timed_out, primary_nav, secondary_nav = _bounded_browser_audit(
                organization, canonical, pages, output_dir, timeout, deadline,
            )
            rows += browser_rows
            generic_complete = not browser_timed_out
            if browser_timed_out: timed_out = True
        # Gate 2: rank dead pages/links by live-nav reachability before they read as high-confidence.
        apply_nav_reachability_gate(rows, primary_nav, secondary_nav, timeout, deadline)
        if migrated_from:
            rows = suppress_origin_findings(rows, migrated_from)
            rows.append(migration_finding(organization, homepage, canonical))
        fast_complete = bounded_complete and generic_complete and time.monotonic() <= deadline
        if not fast_complete:
            timed_out = timed_out or time.monotonic() > deadline
            subsystem_errors.append(f"fast_audit: organization reached the {ORG_DEADLINE_SECONDS}-second limit")
    except Exception as exc:
        # A hang past the deadline is not a data failure: mark it timed_out so coverage already
        # gathered is salvaged as partial rather than discarded as an empty scan.
        if time.monotonic() >= deadline:
            timed_out = True
        subsystem_errors.append(f"fast_audit: {(str(exc).splitlines() or [exc.__class__.__name__])[0]}")
    if deep_revenue:
        print(f"[{index}] {organization}: revenue path verifier", flush=True)
        try:
            revenue_dir = output_dir / "revenue-verifier" / re.sub(r"[^a-z0-9]+", "-", organization.lower()).strip("-")
            revenue_evidence = _run_stable_revenue_verifier(
                organization, canonical, revenue_dir, timeout, time.monotonic() + 300,
            )
            rows += _revenue_results(organization, revenue_evidence)
            controls_count += len(revenue_evidence); deep_complete = True
        except Exception as exc:
            subsystem_errors.append(f"deep_revenue: {str(exc).splitlines()[0]}")
    findings = rank_findings(deduplicate_results(enrich_findings(rows)))
    high = sum(row.confidence == "high" for row in findings)
    medium = sum(row.confidence == "medium" for row in findings)
    low = sum(row.confidence == "low" for row in findings)
    inaccessible = sum(bool(p.error) or isinstance(p.status_code, int) and p.status_code >= 400 for p in pages)
    fast_errors = [error for error in subsystem_errors if error.startswith("fast_audit:")]
    sufficient, coverage_status, homepage_complete = _coverage_status(
        pages, desktop_count, mobile_count,
        fast_complete, bounded_complete, generic_complete, fast_errors, timed_out,
    )
    elapsed = time.monotonic() - started
    # pages_discovered = distinct pages of this site we found, not every link seen: external
    # links and repeats of an already-known page are not additional pages.
    distinct_skipped = sum(s.reason not in {"different_origin", "duplicate_normalized_url"} for s in skips)
    coverage = CoverageRow(
        organization, homepage, len(pages) + distinct_skipped, len(pages),
        " | ".join(page.url for page in pages), len(skips),
        " | ".join(f"{s.url} [{s.reason}]" for s in skips), links, assets,
        desktop_count, mobile_count, controls_count, forms_count, inaccessible,
        round(elapsed, 3), sufficient, coverage_status, homepage_complete,
        bounded_complete, generic_complete, fast_complete, deep_revenue,
        deep_complete, " | ".join(subsystem_errors),
    )
    # A genuinely empty scan reads as insufficient. A partial (budget-salvaged) scan still surfaces
    # its findings (a real failure is real whether or not coverage completed) while coverage_status
    # records that the scan did not finish; a partial scan with no findings reads as partial_coverage.
    if not sufficient and coverage_status == "insufficient_coverage":
        outcome = "insufficient_coverage"
    elif high:
        outcome = "high_confidence_findings"
    elif findings:
        outcome = "findings_present"
    elif coverage_status == "partial_coverage":
        outcome = "partial_coverage"
    else:
        outcome = "clean"
    summary = OrganizationSummaryRow(organization, homepage, high, medium, low, len(opportunities), outcome)
    print(f"[{index}] {organization}: complete status={coverage_status} runtime={elapsed:.1f}s", flush=True)
    # collect_html hands the already-crawled page HTML back to callers that want to reuse it (the web
    # tool's form-health check parses forms from it, avoiding a second crawl or browser render). Kept
    # optional so the batch path (run_audit_v2) pays no extra pickling cost. Appended last so existing
    # positional unpacking is unaffected.
    page_html = [(p.url, p.body) for p in pages if p.body] if collect_html else []
    return index, findings, opportunities, coverage, summary, page_html


def run_audit_v2(
    input_path: Path, output_dir: Path, timeout: float = 20, deep_revenue: bool = True, workers: int = 2,
) -> tuple[list[ResultRow], list[OpportunityRow], list[CoverageRow], list[OrganizationSummaryRow]]:
    organizations = list(read_organizations(input_path))
    completed: dict[int, tuple[list[ResultRow], list[OpportunityRow], CoverageRow, OrganizationSummaryRow]] = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_audit_organization, index, organization, homepage, input_path, output_dir, timeout, deep_revenue): index
            for index, (organization, homepage) in enumerate(organizations, 1)
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result(); completed[result[0]] = result[1:]
            ordered = [completed[key] for key in sorted(completed)]
            findings = [row for item in ordered for row in item[0]]
            opportunities = [row for item in ordered for row in item[1]]
            coverage = [item[2] for item in ordered]; summaries = [item[3] for item in ordered]
            _write_outputs(output_dir, findings, opportunities, coverage, summaries)
    ordered = [completed[key] for key in sorted(completed)]
    return (
        [row for item in ordered for row in item[0]],
        [row for item in ordered for row in item[1]],
        [item[2] for item in ordered], [item[3] for item in ordered],
    )
