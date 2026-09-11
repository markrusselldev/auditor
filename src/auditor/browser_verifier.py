from __future__ import annotations

import csv
import os
import re
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from auditor import security
from auditor.ai_visibility import _fetch_text
from auditor.scanner import read_organizations

# Reachability actively navigates every donation/ticket/registration/contact control it finds on the
# audited site, to depth 2. A site with a large first-party events or ticketing section (its own shop
# or a hosted ticketing subdomain) can carry dozens of these, and clicking them all overruns the
# scan's time budget. A per-site wall-clock budget bounds that phase: once it is spent, the verifier
# stops taking on new controls and finalizes with what it has checked. Ships as config; 0 = unlimited.
DEFAULT_REACHABILITY_BUDGET_SECONDS = 60.0


def reachability_budget_seconds(override: float | None = None) -> float:
    """The per-site reachability budget in seconds (0 = unlimited). An explicit override wins;
    otherwise AUDITOR_REACHABILITY_BUDGET_SECONDS, falling back to the default on a bad value."""
    if override is not None:
        return override
    raw = os.environ.get("AUDITOR_REACHABILITY_BUDGET_SECONDS")
    if raw is None:
        return DEFAULT_REACHABILITY_BUDGET_SECONDS
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_REACHABILITY_BUDGET_SECONDS


def _budget_exhausted(deadline: float | None, now: float) -> bool:
    return deadline is not None and now >= deadline


def all_organizations(input_path: Path) -> tuple[str, ...]:
    return tuple(organization for organization, _url in read_organizations(input_path))


def is_same_site(url: str, homepage: str) -> bool:
    """True when `url` belongs to the same site as the audited `homepage`.

    Same site = same registrable domain, so the audited site's own www/apex and subdomains all
    count as first-party. Bare IPs and localhost have no registrable domain, so those fall back to
    a hostname match (which keeps the loopback test fixtures first-party to themselves). Reachability
    stays within the audited site: a revenue or contact link that leads to an external platform is
    confirmed by whether it loads, not by traversing the destination's own pages.
    """
    home_registrable = security.registrable_domain(homepage)
    url_registrable = security.registrable_domain(url)
    if home_registrable and url_registrable:
        return home_registrable == url_registrable
    return (urlsplit(url).hostname or "").lower() == (urlsplit(homepage).hostname or "").lower()


def should_crawl_destination(
    *,
    resulting_url: str,
    homepage: str,
    verification_result: str,
    interaction_result: str,
    next_depth: int,
    visited: set[str],
) -> bool:
    """Whether a verified control's destination should itself be inspected for further controls.

    We only ever descend into the audited site's own pages (a first-party revenue funnel). A
    destination that loads on an external platform is already confirmed reachable by the control
    check; we do not crawl it. Broken, non-navigating, and known terminal transaction interfaces
    are never descended into either, and the depth/visited budget still applies.
    """
    return (
        verification_result != "confirmed_broken"
        and interaction_result not in {"form", "non-web-action", "none"}
        and is_same_site(resulting_url, homepage)
        and not is_terminal_interface(resulting_url)
        and should_visit_destination(resulting_url, next_depth, visited)
    )

CATEGORY_PATTERNS = (
    ("donation", re.compile(r"\b(donate|donation|give|giving|support us)\b", re.I)),
    ("ticket", re.compile(r"\b(tickets?|box office|buy tickets?|purchase tickets?)\b", re.I)),
    ("registration", re.compile(r"\b(register|registration|rsvp)\b", re.I)),
    ("membership", re.compile(r"\b(membership|become a member|join|renew)\b", re.I)),
    ("ecommerce", re.compile(r"\b(shop|purchase|add to (?:cart|pouch)|cart|checkout)\b", re.I)),
    ("contact", re.compile(r"\b(contact|email us|get in touch)\b", re.I)),
)

ERROR_PATTERNS = (
    re.compile(r"\b404\b.*\b(not found|error)\b", re.I | re.S),
    re.compile(r"\b(page|file|site) (was |is )?not found\b", re.I),
    re.compile(r"\b(page|service|website|tickets?) (is |are )?(currently )?unavailable\b", re.I),
    re.compile(r"\ban error has occurred\b", re.I),
    re.compile(r"\binternal server error\b", re.I),
    re.compile(r"\bthis site can['\u2019]?t be reached\b", re.I),
)

PARKED_SITE_PATTERNS = (
    re.compile(r"\b(?:this |the )?domain (?:is |may be )?(?:parked|for sale)\b", re.I),
    re.compile(r"\bparked free\b", re.I),
    re.compile(r"\b(?:buy|get) this domain\b", re.I),
)
UNAVAILABLE_SITE_PATTERNS = (
    re.compile(r"\bwe (?:are|'re|\u2019re) rebuilding (?:our|the) (?:site|website)\b", re.I),
    re.compile(r"\b(?:site|website) (?:is )?(?:under construction|coming soon)\b", re.I),
    re.compile(r"\b(?:site|website) (?:is |will be )?(?:temporarily )?unavailable\b", re.I),
)
# A donation destination stuck in a payment provider's test/sandbox/demo environment does not take
# real money - a genuine failure. Match the environment PHRASE ("test mode", "sandbox mode"), never a
# bare word: "demo" alone appears in ordinary marketing copy ("Request a demo") on working donation
# platforms, so matching it flags a live donation host as broken.
TEST_DONATION_PATTERN = re.compile(
    r"\btest[- _]?form\d*\b|\b(?:test|staging|sandbox|demo)[- ]?mode\b|\bsandbox environment\b",
    re.I,
)

TARGET_CATEGORY_PATTERNS = (
    ("donation", re.compile(r"(^|[-_/])(donate|donation|giving|give|support-us)([-_/.]|$)", re.I)),
    ("ticket", re.compile(r"(^|[-_/])(tickets?|box-office)([-_/.]|$)", re.I)),
    ("registration", re.compile(r"(^|[-_/])(register|registration|rsvp)([-_/.]|$)", re.I)),
    ("membership", re.compile(r"(^|[-_/])membership([-_/.]|$)", re.I)),
    ("ecommerce", re.compile(r"(^|[-_/])(shop|store|cart|checkout)([-_/.]|$)", re.I)),
    ("contact", re.compile(r"(^|[-_/])contact([-_/.]|$)", re.I)),
)

NON_WEB_SCHEMES = {"mailto", "tel", "webcal"}
CONTROL_SELECTOR = "a, button, input[type=button], input[type=submit], input[type=image], [role=button], [role=link]"
BROWSER_FAILURE_MARKERS = (
    "ERR_NAME_NOT_RESOLVED",
    "ERR_CONNECTION_REFUSED",
    "ERR_ADDRESS_UNREACHABLE",
    "ERR_INVALID_URL",
    "ERR_TUNNEL_CONNECTION_FAILED",
)

_NAV_REVERIFY_DELAY_SECONDS = 2.0
_NAV_REVERIFY_TIMEOUT = 15.0


def _navigation_error_survives_recheck(url: str, navigation_error: str) -> str:
    """A transient DNS/connection navigation failure (ERR_NAME_NOT_RESOLVED and the like) is
    client-specific and often resolves for a real visitor. Re-verify the url once with the independent
    HTTP client before the error stands: if it now reaches a live page (any non-dead status) the
    browser failure was a momentary blip and the error is cleared; a transport error or a 404/410/5xx
    on the re-check keeps it. Non-network errors (a click timeout, an inconclusive action) are returned
    unchanged - decide_result handles those as before."""
    if not navigation_error or not any(m in navigation_error for m in BROWSER_FAILURE_MARKERS):
        return navigation_error
    time.sleep(_NAV_REVERIFY_DELAY_SECONDS)
    status, _final, _body = _fetch_text(url, _NAV_REVERIFY_TIMEOUT)
    reachable = isinstance(status, int) and not (status in {404, 410} or status >= 500)
    return "" if reachable else navigation_error


@dataclass(frozen=True, slots=True)
class Control:
    category: str
    name: str
    control_type: str
    target: str
    source_page: str
    frame_url: str
    frame_index: int
    element_index: int
    submit_risk: bool


@dataclass(slots=True)
class BrowserEvidence:
    organization: str
    homepage: str
    source_page: str
    category: str
    visible_control: str
    control_type: str
    original_target: str
    resulting_url: str
    interaction_result: str
    main_document_status: int | str
    visible_error_text: str
    browser_or_network_error: str
    screenshot_path: str
    verification_result: str
    evidence: str


@dataclass(slots=True)
class BrowserSummary:
    organization: str
    homepage: str
    controls_reviewed: int
    confirmed_broken: int
    appears_functional: int
    needs_manual_review: int
    outreach_eligible_confirmed: int
    scan_outcome: str


def classify_control(
    name: str,
    title: str = "",
    target: str = "",
    surrounding_context: str = "",
) -> str | None:
    candidate = " ".join(f"{name} {title}".split())
    if not candidate:
        return None
    context = " ".join(surrounding_context.split())
    combined = f"{candidate} {context} {target}"
    if re.search(r"\b(create|register for an?) account\b", combined, re.I):
        return None
    if re.search(r"/account/(register|create)", target, re.I):
        return None
    if re.search(r"\b(newsletter|mailing list|subscribe|sign up for (?:news|updates))\b", combined, re.I):
        return None
    if re.fullmatch(r"join!?", candidate, re.I) and not re.search(
        r"\b(member|membership|neoncrm|join-give)\b", combined, re.I,
    ):
        return None
    if re.fullmatch(r"skip to (?:main )?content", candidate, re.I):
        return None
    educational = re.search(
        r"\b(register|registration|apply|returning student|student|orientation|ged|"
        r"high school equivalency|academics|services|payment deadlines)\b",
        candidate,
        re.I,
    )
    if educational and re.search(
        r"\b(student|college|academic|education|ged)\b", combined, re.I,
    ):
        return None
    if re.fullmatch(r"(calendar|previous|next|today|[0-9]{1,2})", candidate, re.I):
        return None
    if re.search(
        r"\b(request more information|inquire|inquiry|schedule a call|appointment|"
        r"reservation|price request|artwork inquiry|inventory inquiry)\b",
        candidate,
        re.I,
    ):
        return "contact"
    if re.fullmatch(r"send(?: message)?", candidate, re.I) and re.search(
        r"\b(contact|inquir|message|name|email)\b", combined, re.I,
    ):
        return "contact"
    if re.fullmatch(r"(?:apply|renew|join)", candidate, re.I) and re.search(
        r"\b(member|membership|neoncrm)\b", combined, re.I,
    ):
        return "membership"
    if re.fullmatch(r"(?:make a gift|sponsor)", candidate, re.I):
        return "donation"
    if re.search(r"\bevents?\b", candidate, re.I) and re.search(r"/events?/?$", urlsplit(target).path, re.I):
        return "registration"
    for category, pattern in CATEGORY_PATTERNS:
        if pattern.search(candidate):
            return category
    path = urlsplit(target).path
    for category, pattern in TARGET_CATEGORY_PATTERNS:
        if pattern.search(path):
            return category
    return None


def is_intentional_non_web_action(target: str) -> bool:
    return urlsplit(target).scheme.lower() in NON_WEB_SCHEMES


def find_visible_error(text: str) -> str:
    compact = " ".join(text.split())
    if "didn't load Google Maps correctly" in compact:
        compact = re.sub(
            r"Oops! Something went wrong\. This page didn't load Google Maps correctly\.[^.]*\.",
            "",
            compact,
            flags=re.I,
        )
    for pattern in ERROR_PATTERNS:
        match = pattern.search(compact)
        if match:
            start = max(0, match.start() - 80)
            end = min(len(compact), match.end() + 120)
            return compact[start:end]
    return ""


# A genuine "under construction / rebuilding / coming soon" page is a sparse PLACEHOLDER - little
# beyond the notice itself. A fully functional page (forms, content, navigation) can carry a "we're
# improving things" banner while working perfectly, so on a content-rich page that phrase is a
# notice, not a failure. This many characters of visible text separates a stub from a real page.
_PLACEHOLDER_MAX_CHARS = 800


def find_explicit_failure(text: str, url: str, category: str = "") -> str:
    compact = " ".join(text.split())

    def _snippet(match) -> str:
        return compact[max(0, match.start() - 80):min(len(compact), match.end() + 120)]

    # Parked/for-sale pages are flagged regardless of length (a squatter's lander can be long).
    for pattern in PARKED_SITE_PATTERNS:
        match = pattern.search(compact)
        if match:
            return _snippet(match)
    # "Unavailable/rebuilding/under-construction" only counts as a failure on a placeholder-sized page.
    if len(compact) < _PLACEHOLDER_MAX_CHARS:
        for pattern in UNAVAILABLE_SITE_PATTERNS:
            match = pattern.search(compact)
            if match:
                return _snippet(match)
    if category == "donation":
        test_evidence = f"{url} {compact}"
        match = TEST_DONATION_PATTERN.search(test_evidence)
        if match:
            start = max(0, match.start() - 80)
            end = min(len(test_evidence), match.end() + 120)
            return test_evidence[start:end]
    return ""


def decide_result(
    *,
    status: int | str,
    navigation_error: str,
    visible_error: str,
    submit_risk: bool,
    non_web_action: bool,
    interaction_result: str,
) -> tuple[str, str]:
    if non_web_action:
        return "appears_functional", "Intentional non-web action; not activated"
    if submit_risk:
        return "needs_manual_review", "Submit-capable form control was not activated"
    if navigation_error and any(marker in navigation_error for marker in BROWSER_FAILURE_MARKERS):
        return "confirmed_broken", f"Browser navigation failed: {navigation_error}"
    if isinstance(status, int) and (status in {404, 410} or status >= 500):
        return "confirmed_broken", f"Main document returned HTTP {status}"
    if visible_error:
        return "confirmed_broken", f"Visitor-visible error: {visible_error}"
    if isinstance(status, int) and status in {401, 403, 429}:
        return "needs_manual_review", f"HTTP {status} may be bot protection or access policy"
    if navigation_error:
        return "needs_manual_review", f"Browser action was inconclusive: {navigation_error}"
    if interaction_result in {"same-tab", "popup", "modal", "iframe"}:
        return "appears_functional", f"Visible control produced a {interaction_result} result"
    return "needs_manual_review", "No conclusive navigation, modal, or visible error"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:70] or "control"


def _short_label(text: str, limit: int = 80) -> str:
    """A control's visible label should read like a button or link, not a paragraph. When a whole
    sentence is wrapped in an anchor, its link text is trimmed to a readable snippet on a word
    boundary so a finding names the control cleanly. Whitespace is normalized to single spaces."""
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0] or text[:limit]
    return cut.rstrip() + "..."


def _control_name(locator) -> tuple[str, str, str, str, bool, str]:
    values = locator.evaluate(
        """el => ({
          tag: el.tagName.toLowerCase(),
          role: el.getAttribute('role') || '',
          aria: el.getAttribute('aria-label') || '',
          title: el.getAttribute('title') || '',
          text: (el.innerText || el.value || '').trim(),
          alt: el.getAttribute('alt') || el.querySelector('img[alt]')?.getAttribute('alt') || '',
          href: el.href || el.getAttribute('formaction') || '',
          type: el.getAttribute('type') || '',
          inForm: !!el.closest('form'),
          context: (el.closest('form')?.innerText || el.closest('section')?.innerText || el.parentElement?.parentElement?.innerText || '').slice(0, 2000)
        })"""
    )
    name = " ".join((values["aria"] or values["text"] or values["alt"] or values["title"]).split())
    control_type = values["role"] or values["tag"]
    submit_risk = (
        values["tag"] == "input" and values["type"].lower() in {"submit", "image"}
    ) or (
        values["tag"] == "button"
        and values["inForm"]
        and values["type"].lower() not in {"button", "reset"}
    )
    return name, control_type, values["href"], values["title"], submit_risk, values["context"]


def normalize_destination(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    hostname = parsed.hostname.lower()
    port = parsed.port
    netloc = hostname
    if port and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
        netloc = f"{hostname}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def normalize_control_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", label.lower()).strip()


def should_visit_destination(url: str, depth: int, visited: set[str], max_depth: int = 2) -> bool:
    normalized = normalize_destination(url)
    hostname = (urlsplit(normalized).hostname or "").lower()
    social_share = any(hostname == suffix or hostname.endswith(f".{suffix}") for suffix in (
        "facebook.com", "pinterest.com", "twitter.com", "x.com", "linkedin.com",
        "youtube.com", "instagram.com",
    ))
    return bool(normalized and not social_share and depth <= max_depth and normalized not in visited)


def is_terminal_interface(url: str) -> bool:
    hostname = (urlsplit(url).hostname or "").lower()
    return any(hostname == suffix or hostname.endswith(f".{suffix}") for suffix in (
        "holdmyticket.com", "runsignup.com", "ticketsignup.io", "qgiv.com",
        "bloomerang.co", "neoncrm.com", "onecause.com", "paypal.com",
    ))


@dataclass
class EcommerceTraversalState:
    listing_url: str = ""
    product_url: str = ""
    cart_url: str = ""
    checkout_url: str = ""
    product_action_evaluated: bool = False
    add_to_cart_evaluated: bool = False


def ecommerce_destination_kind(url: str, label: str = "") -> str:
    parsed = urlsplit(normalize_destination(url))
    path = parsed.path.lower().rstrip("/")
    query = parsed.query.lower()
    text = " ".join(label.lower().split())
    if re.search(r"\bcheckout\b", text) or re.search(r"/(?:checkout)(?:/|$)", path):
        return "checkout"
    if re.search(r"^(?:view |shopping )*(?:cart|basket)\b", text) or re.search(r"/(?:cart|basket)(?:/|$)", path):
        return "cart"
    if (
        re.search(r"/(?:products?|product-page|p)/", f"{path}/")
        or re.search(r"/shop/[^/]+/[^/]+(?:/|$)", f"{path}/")
    ):
        return "product"
    if (
        re.search(r"\b(?:shop|store|inventory|collection)\b", text)
        or re.search(r"/(?:shop|store|buy|artworks?|inventory|collections?|category)(?:/|$)", f"{path}/")
    ):
        return "listing"
    if re.search(r"(?:^|&)(?:page|p|sort|filter|order|view)=", query):
        return "listing"
    return ""


def ecommerce_destination_allowed(
    state: EcommerceTraversalState, url: str, label: str = "", reserve: bool = False,
) -> bool:
    normalized = normalize_destination(url)
    if not normalized:
        return False
    parsed = urlsplit(normalized)
    if re.search(r"(?:^|&)(?:page|p|sort|filter|order|view)=", parsed.query, re.I):
        return False
    kind = ecommerce_destination_kind(normalized, label)
    if not kind:
        return True
    field = f"{kind}_url"
    existing = getattr(state, field)
    allowed = not existing or existing == normalized
    if allowed and reserve and not existing:
        setattr(state, field, normalized)
    return allowed


def filter_ecommerce_controls(
    controls: list[Control], source_url: str, state: EcommerceTraversalState,
) -> list[Control]:
    source_kind = ecommerce_destination_kind(source_url)
    filtered: list[Control] = []
    for control in controls:
        if control.category != "ecommerce":
            filtered.append(control)
            continue
        label = " ".join(control.name.lower().split())
        target_kind = ecommerce_destination_kind(control.target, label)
        add_to_cart = bool(re.search(r"\badd to (?:cart|pouch)\b", label))
        inventory_action = target_kind == "product" or add_to_cart
        if control.target and target_kind in {"listing", "product", "cart", "checkout"} and not ecommerce_destination_allowed(
            state, control.target, label,
        ):
            continue
        if source_kind == "listing" and inventory_action:
            if add_to_cart:
                if state.add_to_cart_evaluated:
                    continue
                state.add_to_cart_evaluated = True
            else:
                if state.product_action_evaluated:
                    continue
                state.product_action_evaluated = True
        elif add_to_cart:
            if state.add_to_cart_evaluated:
                continue
            state.add_to_cart_evaluated = True
        filtered.append(control)
    return filtered


def discover_controls(page) -> list[Control]:
    controls: list[Control] = []
    seen: set[tuple[str, str, str, str, int, int]] = set()
    for frame_index, frame in enumerate(page.frames):
        representative_product = False
        representative_events = 0
        locators = frame.locator(CONTROL_SELECTOR)
        try:
            count = locators.count()
        except Exception:
            continue
        for element_index in range(count):
            locator = locators.nth(element_index)
            try:
                if not locator.is_visible():
                    continue
                name, control_type, target, title, submit_risk, context = _control_name(locator)
            except Exception:
                continue
            category = classify_control(name, title, target, f"{context} {page.url}")
            if not locator.is_enabled() and not submit_risk:
                continue
            path = urlsplit(target).path
            product_path = bool(re.search(
                r"/(?:products?|product-page|shop/.+|[^/]+-gift-shop/p)/", path, re.I,
            ))
            explicit_ecommerce = bool(re.search(
                r"\b(shop|purchase|add to (?:cart|pouch)|cart|checkout)\b",
                f"{name} {title}", re.I,
            ))
            source_path = urlsplit(page.url).path.rstrip("/")
            listing_page = bool(re.search(
                r"/(?:[^/]+-)?(?:gift-)?shop$", source_path, re.I,
            ))
            if (
                category == "ecommerce"
                and not explicit_ecommerce
                and (
                    urlsplit(target).path.rstrip("/") == source_path
                    or listing_page
                )
            ):
                category = None
            if listing_page and re.fullmatch(r"purchase", " ".join(f"{name} {title}".split()), re.I):
                if representative_product:
                    category = None
                else:
                    category = "ecommerce"
                    representative_product = True
            elif product_path and listing_page:
                category = None
            elif product_path and not explicit_ecommerce:
                if representative_product:
                    category = None
                else:
                    category = "ecommerce"
                    representative_product = True
            if not category and control_type in {"a", "link"}:
                if (
                    representative_events < 2
                    and re.search(r"/events?/.+", path, re.I)
                    and re.search(r"/events?$", source_path, re.I)
                ):
                    category = "registration"
                    representative_events += 1
            if not category:
                continue
            key = (category, name.lower(), target, frame.url, frame_index, element_index)
            if key in seen:
                continue
            seen.add(key)
            controls.append(Control(
                category, name or title, control_type, target, page.url, frame.url,
                frame_index, element_index, submit_risk,
            ))
    return controls


def _fresh_locator(page, control: Control):
    frames = page.frames
    frame = next((item for item in frames if item.url == control.frame_url), None)
    if frame is None and control.frame_index < len(frames):
        frame = frames[control.frame_index]
    if frame is None:
        raise RuntimeError("Original iframe is no longer available")
    locators = frame.locator(CONTROL_SELECTOR)
    if control.element_index >= locators.count():
        raise RuntimeError("Control is no longer present at its original position")
    locator = locators.nth(control.element_index)
    name, _kind, target, title, submit_risk, context = _control_name(locator)
    classified = classify_control(name, title, target, f"{context} {page.url}")
    if classified is None and control.category in {"ecommerce", "registration"}:
        classified = control.category
    if classified != control.category:
        raise RuntimeError("Control changed between discovery and verification")
    return locator, target, submit_risk, frame != page.main_frame


def _screenshot(page, path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        page.screenshot(path=str(path), full_page=True, animations="disabled")
        return str(path)
    except Exception as exc:
        return f"screenshot_failed: {exc}"


def verify_control(browser, organization: str, homepage: str, control: Control, path: Path, timeout_ms: int) -> BrowserEvidence:
    context = browser.new_context(
        viewport={"width": 1440, "height": 1000},
        user_agent="AuditorBrowserValidation/1.0 (+https://markrussell.io)",
    )
    page = context.new_page()
    page.set_default_timeout(timeout_ms)
    navigation_responses: list[object] = []
    failed_navigations: list[str] = []
    context.on(
        "response",
        lambda response: navigation_responses.append(response)
        if response.request.is_navigation_request()
        else None,
    )
    context.on(
        "requestfailed",
        lambda request: failed_navigations.append(request.failure or "Navigation failed")
        if request.is_navigation_request()
        else None,
    )
    navigation_status: int | str = ""
    navigation_error = ""
    visible_error = ""
    resulting_url = homepage
    interaction_result = "none"
    target = control.target
    try:
        response = page.goto(control.source_page, wait_until="domcontentloaded", timeout=timeout_ms)
        if response is not None:
            navigation_status = response.status
        page.wait_for_timeout(1500)
        locator, fresh_target, submit_risk, source_is_iframe = _fresh_locator(page, control)
        navigation_responses.clear()
        failed_navigations.clear()
        target = fresh_target or target
        if is_intentional_non_web_action(target):
            interaction_result = "non-web-action"
        elif submit_risk:
            interaction_result = "form"
        else:
            old_url = page.url
            old_frame_count = len(page.frames)
            popup_pages: list[object] = []
            context.on("page", lambda new_page: popup_pages.append(new_page))
            locator.scroll_into_view_if_needed()
            click_error = ""
            try:
                locator.click(timeout=min(timeout_ms, 5000), no_wait_after=True)
            except Exception as exc:
                click_error = str(exc).splitlines()[0][:500]
                parsed_target = urlsplit(target)
                if control.control_type in {"a", "link"} and parsed_target.scheme in {"http", "https"}:
                    try:
                        response = page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
                        if response is not None:
                            navigation_status = response.status
                        interaction_result = "direct-anchor-fallback"
                    except Exception as navigation_exc:
                        navigation_error = str(navigation_exc).splitlines()[0][:500]
                else:
                    navigation_error = click_error
            page.wait_for_timeout(2500)
            active_page = page
            if popup_pages:
                active_page = popup_pages[-1]
                try:
                    active_page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
                except Exception:
                    pass
                interaction_result = "popup"
            elif page.url != old_url and interaction_result != "direct-anchor-fallback":
                interaction_result = "iframe" if source_is_iframe else "same-tab"
            else:
                dialogs = page.locator('[role="dialog"]:visible, dialog[open]')
                if dialogs.count() and interaction_result == "none":
                    interaction_result = "modal"
                elif (len(page.frames) > old_frame_count or source_is_iframe) and interaction_result == "none":
                    interaction_result = "iframe"
            resulting_url = active_page.url
            matching_responses = [
                item for item in navigation_responses
                if item.frame == active_page.main_frame
            ]
            if matching_responses:
                navigation_status = matching_responses[-1].status
            if failed_navigations and not navigation_error:
                navigation_error = failed_navigations[-1][:500]
            try:
                body_text = active_page.locator("body").inner_text(timeout=3000)
                visible_error = (
                    find_visible_error(body_text)
                    or find_explicit_failure(body_text, resulting_url, control.category)
                )
            except Exception:
                body_text = ""
            page = active_page
    except Exception as exc:
        message = str(exc)
        if "Control" in message or "iframe" in message:
            navigation_error = ""
            interaction_result = "control-unavailable"
        else:
            navigation_error = message.splitlines()[0][:500]
    screenshot = _screenshot(page, path)
    # A transient DNS/connection failure while following the control is re-verified before it counts
    # as a broken revenue path (a real visitor often reaches the page fine).
    navigation_error = _navigation_error_survives_recheck(target, navigation_error)
    result, reason = decide_result(
        status=navigation_status,
        navigation_error=navigation_error,
        visible_error=visible_error,
        submit_risk=control.submit_risk,
        non_web_action=is_intentional_non_web_action(target),
        interaction_result=interaction_result,
    )
    if interaction_result == "control-unavailable":
        result = "needs_manual_review"
        reason = "Visible control could not be relocated safely on a fresh page"
    evidence = BrowserEvidence(
        organization, homepage, control.source_page, control.category, _short_label(control.name),
        control.control_type, target, resulting_url, interaction_result,
        navigation_status, visible_error, navigation_error, screenshot,
        result, reason,
    )
    context.close()
    return evidence


def _write_csv(rows: list[object], path: Path, row_type: type) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row_type.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)


def run_browser_validation(
    input_path: Path,
    output_dir: Path,
    names: tuple[str, ...],
    timeout_seconds: float,
    *,
    budget_seconds: float | None = None,
) -> tuple[list[BrowserEvidence], list[BrowserSummary]]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Python Playwright is unavailable; use scripts/browser-verify-docker"
        ) from exc
    organizations = dict(read_organizations(input_path))
    missing = [name for name in names if name not in organizations]
    if missing:
        raise ValueError(f"Organizations missing from input CSV: {', '.join(missing)}")
    output_dir.mkdir(parents=True, exist_ok=True)
    screenshots = output_dir / "screenshots"
    if screenshots.exists():
        shutil.rmtree(screenshots)
    evidence_rows: list[BrowserEvidence] = []
    summaries: list[BrowserSummary] = []
    timeout_ms = round(timeout_seconds * 1000)
    budget = reachability_budget_seconds(budget_seconds)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])
        for org_index, organization in enumerate(names, 1):
            homepage = organizations[organization]
            print(f"[{org_index}/{len(names)}] {organization}: loading homepage", flush=True)
            discovery_error = ""
            homepage_screenshot = screenshots / f"{org_index:02d}-{_slug(organization)}-homepage.png"
            organization_rows: list[BrowserEvidence] = []
            pending: list[tuple[str, int]] = [(homepage, 0)]
            visited: set[str] = set()
            seen_controls: set[tuple[str, ...]] = set()
            ecommerce_state = EcommerceTraversalState()
            # Per-site wall-clock budget (0 = unlimited). Once spent, stop taking on new pages or
            # controls and finalize with what was checked, so one control-heavy site cannot run away
            # with the whole scan.
            deadline = time.monotonic() + budget if budget > 0 else None
            budget_reached = False
            while pending:
                if _budget_exhausted(deadline, time.monotonic()):
                    budget_reached = True
                    break
                source_page, depth = pending.pop(0)
                normalized_source = normalize_destination(source_page)
                if not should_visit_destination(source_page, depth, visited):
                    continue
                visited.add(normalized_source)
                discovery_context = browser.new_context(
                    viewport={"width": 1440, "height": 1000},
                    user_agent="AuditorBrowserValidation/1.0 (+https://markrussell.io)",
                )
                discovery_page = discovery_context.new_page()
                discovery_page.set_default_timeout(timeout_ms)
                controls: list[Control] = []
                homepage_row: BrowserEvidence | None = None
                try:
                    response = discovery_page.goto(
                        source_page, wait_until="domcontentloaded", timeout=timeout_ms,
                    )
                    discovery_page.wait_for_timeout(2500)
                    controls = discover_controls(discovery_page)
                    if discovery_page.locator(
                        '.carousel, [class*="carousel"], [class*="slider"]'
                    ).count():
                        discovery_page.wait_for_timeout(4000)
                        controls.extend(discover_controls(discovery_page))
                    controls = filter_ecommerce_controls(
                        controls, discovery_page.url, ecommerce_state,
                    )
                    if depth == 0:
                        _screenshot(discovery_page, homepage_screenshot)
                        body_text = discovery_page.locator("body").inner_text(timeout=3000)
                        visible_failure = (
                            find_visible_error(body_text)
                            or find_explicit_failure(body_text, discovery_page.url)
                        )
                        status = response.status if response is not None else ""
                        result, reason = decide_result(
                            status=status, navigation_error="",
                            visible_error=visible_failure, submit_risk=False,
                            non_web_action=False, interaction_result="same-tab",
                        )
                        if result == "confirmed_broken":
                            homepage_row = BrowserEvidence(
                                organization, homepage, homepage, "homepage", "Homepage",
                                "page", homepage, discovery_page.url, "same-tab", status,
                                visible_failure, "", str(homepage_screenshot), result, reason,
                            )
                    print(
                        f"[{org_index}/{len(names)}] {organization}: depth {depth} "
                        f"page {discovery_page.url} has {len(controls)} visible relevant control(s)",
                        flush=True,
                    )
                except Exception as exc:
                    error = str(exc).splitlines()[0][:500]
                    if depth == 0:
                        discovery_error = error
                        _screenshot(discovery_page, homepage_screenshot)
                        print(
                            f"[{org_index}/{len(names)}] {organization}: "
                            f"homepage discovery error: {discovery_error}",
                            flush=True,
                        )
                finally:
                    discovery_context.close()
                if homepage_row is not None:
                    organization_rows.append(homepage_row)
                if discovery_error and depth == 0:
                    discovery_error = _navigation_error_survives_recheck(homepage, discovery_error)
                if discovery_error and depth == 0:
                    result, reason = decide_result(
                        status="", navigation_error=discovery_error, visible_error="",
                        submit_risk=False, non_web_action=False,
                        interaction_result="navigation",
                    )
                    organization_rows.append(BrowserEvidence(
                        organization, homepage, homepage, "homepage", "Homepage",
                        "page", homepage, homepage, "navigation", "", "",
                        discovery_error, str(homepage_screenshot), result,
                        reason if result == "confirmed_broken" else "Homepage could not be inspected reliably",
                    ))
                for control in controls:
                    if _budget_exhausted(deadline, time.monotonic()):
                        budget_reached = True
                        break
                    key = (
                        normalize_destination(control.source_page), control.category,
                        normalize_control_label(control.name),
                        normalize_destination(control.target) or control.target,
                    )
                    if key in seen_controls:
                        continue
                    seen_controls.add(key)
                    control_index = len(organization_rows) + 1
                    print(
                        f"  [{control_index}] depth {depth} {control.category}: {control.name[:70]}",
                        flush=True,
                    )
                    path = screenshots / (
                        f"{org_index:02d}-{_slug(organization)}-{control_index:02d}-"
                        f"{_slug(control.category + '-' + control.name)}.png"
                    )
                    row = verify_control(
                        browser, organization, homepage, control, path, timeout_ms,
                    )
                    organization_rows.append(row)
                    print(f"      -> {row.verification_result}: {row.evidence[:100]}", flush=True)
                    next_depth = depth + 1
                    if should_crawl_destination(
                        resulting_url=row.resulting_url,
                        homepage=homepage,
                        verification_result=row.verification_result,
                        interaction_result=row.interaction_result,
                        next_depth=next_depth,
                        visited=visited,
                    ):
                        if row.category != "ecommerce" or ecommerce_destination_allowed(
                            ecommerce_state, row.resulting_url, row.visible_control, reserve=True,
                        ):
                            pending.append((row.resulting_url, next_depth))
            if budget_reached:
                print(
                    f"[{org_index}/{len(names)}] {organization}: reachability budget "
                    f"({budget:.0f}s) reached after {len(organization_rows)} control(s); "
                    "remaining controls not checked",
                    flush=True,
                )
            evidence_rows.extend(organization_rows)
            confirmed = sum(row.verification_result == "confirmed_broken" for row in organization_rows)
            functional = sum(row.verification_result == "appears_functional" for row in organization_rows)
            manual = sum(row.verification_result == "needs_manual_review" for row in organization_rows)
            outreach = sum(
                row.verification_result == "confirmed_broken"
                and row.category in {"donation", "ticket", "contact", "homepage"}
                for row in organization_rows
            )
            summaries.append(BrowserSummary(
                organization, homepage, len(organization_rows), confirmed,
                functional, manual, outreach,
                "confirmed_breakage" if confirmed else ("manual_review" if manual else "no_confirmed_breakage"),
            ))
            _write_csv(evidence_rows, output_dir / "browser-evidence.csv", BrowserEvidence)
            _write_csv(summaries, output_dir / "organization-summary.csv", BrowserSummary)
            print(
                f"[{org_index}/{len(names)}] {organization}: complete "
                f"({confirmed} broken, {functional} functional, {manual} manual)",
                flush=True,
            )
        browser.close()
    return evidence_rows, summaries
