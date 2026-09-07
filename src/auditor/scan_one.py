"""Single-URL orchestration: the whole scan behind one function.

Deterministic detection first (the existing engine's fast + browser checks, deep-revenue off to
stay fast and in scope; plus the AI-visibility checks), then the LLM turns the compact result into
prose. Returns one JSON-serializable report dict. This is what the web service calls.
"""

from __future__ import annotations

import csv
import os
import re
import tempfile
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from auditor import security
from auditor.accessibility import accessibility_findings, accessibility_summary
from auditor.ai_visibility import _fetch_text, run_ai_visibility
from auditor.browser_verifier import run_browser_validation
from auditor.deliverability import check_deliverability, deliverability_findings
from auditor.form_health import apply_form_handlers, detect_forms, findings_from_forms, js_check_pages
from auditor.llm.registry import get_report_provider, visibility_providers
from auditor.mixed_content import mixed_content_findings
from auditor.page_basics import basics_findings
from auditor.performance import performance_findings
from auditor.revenue_verify import verify_revenue_forms
from auditor.report import _grade, build_compact, first_impression, write_report
from auditor.site_profile import build_site_profile
from auditor.textnorm import normalize_scraped_text
from auditor.www_check import check_www_canonical

# The deep form test fills and submits, so it is consent-gated and hard-capped low per scan (a
# backstop, not a coverage promise; the free scan is homepage + a few pages). Ships as config.
# Free-scan scope is set by what the visitor enters: a homepage (root URL) crawls a few top pages;
# a specific page URL scans only that one page. Homepage page count ships as config.
FREE_HOMEPAGE_MAX_PAGES = int(os.environ.get("AUDITOR_FREE_MAX_PAGES", "4"))  # homepage + ~3 top pages
REVENUE_VERIFY_PAGE_CAP = 5
# Engine findings suppressed from the owner-facing web report: redundant with a cleaner finding, or
# developer-oriented noise. (They still exist in the batch/CSV path.)
_WEB_SUPPRESSED_ISSUES = {
    "interface_usable_submission_not_tested",  # the Forms section already reports each form
    "visible_site_failure",                    # raw error-page text; the HTTP failure is shown already
    "serious_console_error",                   # console jargon, not an owner-actionable finding
}
# Honest boundary, surfaced to the owner: we confirm the wiring, not server-side acceptance.
REVENUE_VERIFY_DISCLOSURE = (
    "confirms your form is wired to a reachable destination; does not send real data, "
    "so does not confirm the server accepts it."
)


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("A URL is required")
    if len(raw) > 2000:
        raise ValueError("That URL is too long")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        host = parts.hostname           # None when the URL has no real host
        _port = parts.port              # raises ValueError on a non-numeric port (e.g. "9000)")
    except ValueError as exc:
        # Any malformed URL (a stray paren, a bad port) gets one clean message, never a raw
        # Python exception, and only http(s) with a real host is accepted (no file:, javascript:, etc.).
        raise ValueError("Enter a valid http(s) URL") from exc
    if parts.scheme not in ("http", "https") or not host:
        raise ValueError("Enter a valid http(s) URL")
    # A real web address has a registrable domain (a valid public suffix). A single label
    # ("bhghjghjghjghj") or a made-up TLD has none and is not a site we can scan. Localhost and bare
    # IPs also have none, so they pass only under the dev private-hosts flag; the SSRF guard still
    # blocks them in production.
    if not security.registrable_domain(raw) and not security.allow_private_hosts():
        raise ValueError("Enter a real website address, like example.com")
    return raw


def business_name_from(url: str) -> str:
    host = urlsplit(url).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    label = host.split(":")[0].split(".")[0]
    return label.replace("-", " ").title() if label else host


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def scan_url(url: str, timeout: float = 20.0, output_dir: Path | None = None,
             own_site: bool = False) -> dict:
    """Run a full single-URL audit and return the assembled report dict.

    own_site is the "this is my site" consent gate. The deep revenue form test fills and submits
    forms, so it runs ONLY when own_site is True; the public path leaves it OFF by default.
    """
    # Import here so unit tests that stub the engine (and machines without Playwright) can import
    # this module; the heavy engine is only pulled when an actual scan runs.
    from auditor.v2 import _audit_organization

    homepage = normalize_url(url)
    business = business_name_from(homepage)
    # The URL the visitor enters sets the free scope: a root URL scans the homepage plus a few top
    # pages; a specific page URL scans only that one page (depth 0, one page).
    if urlsplit(homepage).path.strip("/"):
        max_pages, max_depth = 1, 0
    else:
        max_pages, max_depth = FREE_HOMEPAGE_MAX_PAGES, 1

    with _output(output_dir) as out:
        _index, findings, _opps, coverage, summary, page_html = _audit_organization(
            1, business, homepage, Path("."), out, timeout, deep_revenue=False, collect_html=True,
            max_pages=max_pages, max_depth=max_depth,
        )
        _status, final_url, homepage_html = _fetch_text(homepage, timeout)
        ai = run_ai_visibility(final_url or homepage, homepage_html, business, visibility_providers())
        pages_for_forms = page_html or [(final_url or homepage, homepage_html)]
        forms = _detect_forms_safe(pages_for_forms, timeout)

        # Render the homepage once (screenshot + headers + timing + gate detection) before scoring,
        # so a blocking interstitial the render finds can be reported as a finding. The same session
        # also verifies JS submit handlers on pages that have empty-action forms (no extra launch).
        png, vision_info = _vision_screenshot(homepage, out, business, timeout, js_check_pages(forms))
        # If the entered site never loaded by any path (no fetched HTML, no crawled pages, no render),
        # it is unreachable: return a clear outcome, not a graded report. A dead site otherwise scores
        # high because there is nothing left to fault.
        if not ((homepage_html or "").strip() or page_html or png):
            return _unreachable_result(homepage, business)
        apply_form_handlers(forms, vision_info.get("form_handlers") or {})

        report_provider = get_report_provider()
        # Static per-page detectors over the already-crawled HTML (no extra fetch or render). Mixed
        # content is a real, externally-visible failure and is scored; page basics are hygiene and
        # are kept OUT of finding_dicts so they never pad the failure count (see build_report below).
        basics = basics_findings(pages_for_forms)
        # The deliverability half of silent form failure: SPF/DMARC live in DNS, not the browser.
        deliverability = check_deliverability(security.registrable_domain(homepage), timeout)
        # Consent-gated deep test: fill+submit each contact/revenue form in a browser to confirm the
        # submit truly fires (revenue_verify.py). OFF unless the owner consented (own_site) - the
        # public path never launches it; its findings are real revenue failures and are scored.
        revenue_findings = (
            verify_revenue_forms(_revenue_form_pages(forms), own_site=True, http_timeout=timeout)
            if own_site else []
        )
        finding_dicts = (
            [asdict(f) for f in findings]
            + findings_from_forms(forms)
            + mixed_content_findings(pages_for_forms)
            + revenue_findings
            + _control_reachability_findings(business, homepage, out, timeout)
            + deliverability_findings(deliverability)
            + check_www_canonical(final_url or homepage, timeout)
            + performance_findings(vision_info.get("web_vitals"))
            + accessibility_findings(vision_info.get("axe"), homepage)
        )
        # Engine findings that are noise in the owner-facing web report: the Forms section already
        # reports each form; the raw error-page text duplicates the HTTP failure that is already
        # shown; console errors are developer jargon, not an owner-actionable finding.
        finding_dicts = [f for f in finding_dicts
                         if f.get("issue_type") not in _WEB_SUPPRESSED_ISSUES]
        # Normalize scraped site text at the boundary before it reaches the report, the model, or
        # the visitor, so website smart-typography artifacts never surface in our output.
        for finding in finding_dicts:
            if finding.get("evidence"):
                finding["evidence"] = normalize_scraped_text(str(finding["evidence"]))
        # Per-check health: an optional check that could not run (no render, no axe, no vitals) must
        # not let its category read as "clean". Passed into scoring so those categories say "not
        # tested" instead of a perfect score, and reused for analytics below.
        checks_health = {
            "browser_render": "ok" if png else "no_data",
            "accessibility": "ok" if vision_info.get("axe") else "no_data",
            "performance": "ok" if vision_info.get("web_vitals") else "no_data",
            "deliverability": "ok" if deliverability else "no_data",
        }
        compact = build_compact(business, homepage, finding_dicts, ai, checks=checks_health)
        written = write_report(report_provider, compact)

        vision = first_impression(report_provider, png, business, homepage)
        vision["model"] = report_provider.name
        checks_health["vision"] = "no_data" if vision.get("insufficient_information") else "ok"
        profile = build_site_profile(homepage_html, vision_info.get("headers"), vision_info.get("timing"))

    # Internal, non-PII facts for private analytics (auditor.web.analytics). Not part of the report
    # shown to the visitor: the web layer records it and strips it before sending the response. Every
    # value describes the scanned site or our own scan run, never the visitor.
    scan_meta = {
        "overall_score": compact["overall_score"],
        "overall_grade": _grade(compact["overall_score"]),
        "total_findings": len(finding_dicts),
        "finding_counts": dict(Counter(str(f.get("issue_type", "")) for f in finding_dicts)),
        "category_scores": {c["name"]: c["score"] for c in compact["categories"]},
        "pages_crawled": len(pages_for_forms),
        "platform": (profile["tech"].get("cms") or "").lower() or None,
        "llm_provider": report_provider.name,
        "llm_offline": report_provider.name == "offline",
        "checks": checks_health,
    }

    return {
        "_analytics": scan_meta,
        "url": homepage,
        "business": business,
        "overall_score": compact["overall_score"],
        "categories": compact["categories"],
        "report": written,
        "site_profile": profile,
        "what_ai_says": ai["what_ai_says"],
        "basics": basics,
        "web_vitals": vision_info.get("web_vitals") or {},
        "accessibility": accessibility_summary(vision_info.get("axe")),
        "deliverability": deliverability,
        "revenue_verify": {"ran": bool(own_site), "disclosure": REVENUE_VERIFY_DISCLOSURE},
        "ai_visibility": {k: ai[k] for k in ("llms_txt", "schema_org", "ai_crawler_access")},
        "first_impression": vision,
        "forms": forms,
        "coverage_status": coverage.coverage_status,
        "scan_outcome": summary.scan_outcome,
        "report_model": report_provider.name,
    }


def _unreachable_result(url: str, business: str) -> dict:
    """A dead or unresolvable entered URL is not a graded report: say plainly we could not reach it.

    The web layer renders the message instead of a grade, and records the scan with outcome
    "unreachable" (null score), so a site that never loaded is never shown as a near-perfect A.
    """
    return {
        "url": url,
        "business": business,
        "unreachable": True,
        "message": ("We could not reach this site. Check the web address, or the site may be down or "
                    "blocking automated visits."),
        "_analytics": {
            "overall_score": None, "overall_grade": None, "total_findings": 0,
            "finding_counts": {}, "category_scores": {}, "pages_crawled": 0,
            "platform": None, "llm_provider": None, "llm_offline": None, "checks": {},
        },
    }


# A blocking overlay (age gate, cookie/consent wall, name-squeeze or newsletter popup) is a
# deliberate design, marketing, or legal choice - not an externally-visible FAILURE - so the scan
# does NOT flag it (the finding anchor excludes subjective design taste). The vision read still takes
# a clean screenshot behind the overlay and notes it as context; it is just never scored as a problem.


def _revenue_form_pages(forms: list[dict]) -> list[str]:
    """Distinct pages holding a contact/revenue-candidate form, capped low for the deep test.

    Mirrors revenue_verify's own candidate rule (interactive + message-bearing) so the browser is
    launched only for pages worth actively submitting, never for search or form-less pages.
    """
    pages: list[str] = []
    for form in forms:
        candidate = (form.get("has_submit") and form.get("field_count", 0) > 0
                     and (form.get("has_email") or form.get("has_message")))
        if candidate and form["page"] not in pages:
            pages.append(form["page"])
    return pages[:REVENUE_VERIFY_PAGE_CAP]


# Revenue/contact controls whose reachability we surface: a dead donate/book/contact link is a
# broken revenue path (the finding anchor). Ecommerce/homepage rows from the verifier stay out of
# the public report for now.
_REACHABILITY_CATEGORIES = {"donation", "ticket", "registration", "membership", "contact"}


def _control_reachability_findings(business: str, homepage: str, out: Path, timeout: float) -> list[dict]:
    """Call the stable browser_verifier to confirm donate/book/contact controls actually resolve.

    This is the same control-reachability the deep_revenue batch path runs; here it runs inline in
    the web scan. It only navigates controls (submit-capable forms are never activated, per the
    stable verifier), so it is safe on the public path and needs no consent gate. Best-effort: a
    verifier failure must never sink the scan.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="auditor-reach-") as directory:
            csv_path = Path(directory) / "organization.csv"
            with csv_path.open("w", encoding="utf-8", newline="") as handle:
                csv.writer(handle).writerows([("organization", "url"), (business, homepage)])
            evidence, _summaries = run_browser_validation(
                csv_path, out / "reachability", (business,), timeout,
            )
    except Exception:
        return []
    findings: list[dict] = []
    for row in evidence:
        # Only a confirmed-broken control is a reproducible failure; functional and manual-review
        # controls are not reported as findings.
        if row.verification_result != "confirmed_broken" or row.category not in _REACHABILITY_CATEGORIES:
            continue
        failed = row.resulting_url or row.original_target
        findings.append({
            "issue_type": f"revenue_path_{row.category}_{row.interaction_result}",
            "confidence": "high",
            "source_url": row.source_page,
            "failed_url": failed,
            # Name the actual control the scan found ("your Donate button") so the finding is
            # concrete, not a generic "a revenue control".
            "evidence": f"{_control_phrase(row)} leads to {failed}, which is broken. {row.evidence}",
            "revenue_relevant": True,
        })
    return findings


def _control_phrase(row) -> str:
    """A human subject for a broken control, naming the real button/link the scan clicked."""
    name = (row.visible_control or "").strip()
    noun = "link" if row.control_type in ("a", "link") else "button"
    return f'Your "{name}" {noun}' if name else f"Your {row.category} {noun}"


def _detect_forms_safe(pages: list[tuple[str, str]], timeout: float) -> list[dict]:
    """Form health is additive: a failure here must never sink the whole scan."""
    try:
        return detect_forms(pages, timeout)
    except Exception:
        return []


def _vision_screenshot(
    homepage: str, out: Path, business: str, timeout: float, form_check_pages: list[str] | None = None,
) -> tuple[bytes | None, dict]:
    """A clean shot plus the render's headers/timing/form-handler checks; falls back to engine shot."""
    info: dict = {}
    try:
        from auditor.vision_capture import capture_for_vision

        png, info = capture_for_vision(homepage, timeout, form_check_pages)
        if png:
            return png, info
    except Exception:
        pass  # a vision-only capture must never fail the scan; fall back to the engine screenshot
    fallback = out / "screenshots" / _slug(business) / "desktop-1.png"
    return (fallback.read_bytes() if fallback.exists() else None), info


class _output:
    """Use a caller-supplied dir, else a self-cleaning temp dir for this scan's artifacts."""

    def __init__(self, output_dir: Path | None) -> None:
        self._given = output_dir
        self._tmp: tempfile.TemporaryDirectory | None = None

    def __enter__(self) -> Path:
        if self._given is not None:
            self._given.mkdir(parents=True, exist_ok=True)
            return self._given
        self._tmp = tempfile.TemporaryDirectory(prefix="auditor-scan-")
        return Path(self._tmp.name)

    def __exit__(self, *exc) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
