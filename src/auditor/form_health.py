"""Form health: how wired-up a site's forms are, without ever submitting them.

Detection is static and browserless: it parses forms from the HTML the crawl already fetched, so it
covers every crawled page for almost no extra cost. For each form it resolves where submissions go
and probes an explicit action endpoint for a dead 404/5xx, the real money-leak signal. Deep
interactive validation (exercising client-side validation in a real browser) is deliberately a v2
concern; it is expensive and needs a render per page.

Honesty rule: an empty or javascript: action is reported as JavaScript-handled, NOT flagged broken,
since most modern contact forms submit by JS. Only an explicit action URL that returns 404/410/5xx
becomes a finding. Forms are never submitted.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from auditor.ai_visibility import _fetch_text
from auditor.browser_verifier import is_same_site

_DEAD_STATUSES = {404, 410}
_FIELD_INPUT_SKIP = {"submit", "button", "hidden", "image", "reset"}


class _FormParser(HTMLParser):
    """Collect each <form> with its action/method, fields, and whether it has a submit control."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._stack: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._stack.append({
                "action_raw": a.get("action"), "method": (a.get("method") or "get").lower(),
                "fields": [], "field_names": [], "has_email": False, "has_message": False,
                "has_submit": False,
            })
            return
        if not self._stack:
            return
        form = self._stack[-1]
        name = (a.get("name") or a.get("id") or "").strip()
        if tag == "input":
            itype = (a.get("type") or "text").lower()
            if itype in ("submit", "image"):
                form["has_submit"] = True
            elif itype not in _FIELD_INPUT_SKIP:
                form["fields"].append(name)
                if name:
                    form["field_names"].append(name)
                if itype == "email" or "email" in name.lower():
                    form["has_email"] = True
        elif tag == "textarea":
            form["fields"].append(name)
            if name:
                form["field_names"].append(name)
            form["has_message"] = True
        elif tag == "select":
            form["fields"].append(name)
            if name:
                form["field_names"].append(name)
        elif tag == "button":
            btype = (a.get("type") or "submit").lower()  # a button in a form defaults to submit
            if btype == "submit":
                form["has_submit"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._stack:
            self.forms.append(self._stack.pop())


def _detect(page_url: str, html: str) -> list[dict]:
    parser = _FormParser()
    try:
        parser.feed(html or "")
    except Exception:
        return []
    for index, form in enumerate(parser.forms):
        form["page"] = page_url
        form["page_index"] = index  # document order, stable when the page is re-rendered for JS checks
        m = [n for n in form["field_names"] if n]
        form["has_message"] = form["has_message"] or any(
            k in n.lower() for n in m for k in ("message", "comment", "inquir")
        )
    return parser.forms


def detect_forms(pages: list[tuple[str, str]], timeout: float = 12.0) -> list[dict]:
    """Detect forms across every crawled (url, html) page, dedupe repeats, classify each."""
    raw: list[dict] = []
    for page_url, html in pages:
        raw += _detect(page_url, html)

    # A footer newsletter form repeats on every page: collapse identical forms (same action + fields)
    # into one record that lists the pages it appears on.
    groups: dict[tuple, dict] = {}
    for form in raw:
        key = (form.get("action_raw") or "", tuple(sorted(form["field_names"])), form["has_submit"])
        group = groups.get(key)
        if group is None:
            groups[key] = {**form, "pages": [form["page"]]}
        elif form["page"] not in group["pages"]:
            group["pages"].append(form["page"])

    reach_cache: dict[str, int | str] = {}
    return [_classify(form, reach_cache, timeout) for form in groups.values()]


def _classify(form: dict, reach_cache: dict, timeout: float) -> dict:
    page_url = form["page"]
    raw = form.get("action_raw")
    stripped = (raw or "").strip()
    issues: list[str] = []
    action_status = None

    if raw is None or stripped in ("", "#"):
        kind, target, note = "same_page", page_url, "Submits to the same page, likely handled by JavaScript"
    elif stripped.lower().startswith("javascript:"):
        kind, target, note = "javascript", "", "Handled by JavaScript, no server action"
    elif stripped.lower().startswith("mailto:"):
        kind, target, note = "mailto", stripped[7:], "Opens the visitor's email client"
    else:
        kind, target, note = "url", urljoin(page_url, stripped), ""
        if urlsplit(target).scheme in ("http", "https"):
            if target not in reach_cache:
                status, _final, _body = _fetch_text(target, timeout)
                reach_cache[target] = status
            action_status = reach_cache[target]
            # A GET probe only proves an endpoint is dead for a form that submits by GET. A form
            # whose action is a hosted third-party service (Mailchimp, PayPal) or a session-gated
            # handler routinely 404/405s a bare GET while accepting POSTs, so a cross-site action is
            # NOT judged dead from our GET. We flag only when the action is on the audited page's own
            # domain, where a 404/5xx is a genuinely dead handler rather than a POST-only endpoint.
            if (
                isinstance(action_status, int)
                and (action_status in _DEAD_STATUSES or action_status >= 500)
                and is_same_site(target, page_url)
            ):
                issues.append("form_action_dead")
                note = f"Submit endpoint returns HTTP {action_status}; submissions may be lost"

    if issues:
        health = "broken"
    elif form.get("has_submit") and len(form.get("fields", [])) > 0:
        health = "healthy"
    else:
        health = "attention"

    return {
        "page": page_url,
        "page_index": form.get("page_index", 0),
        "js_checked": False,
        "pages": form.get("pages", [page_url]),
        "kind": kind,
        "submit_target": target,
        "target_note": note,
        "method": form.get("method", "get"),
        "field_count": len(form.get("fields", [])),
        "field_names": form.get("field_names", [])[:12],
        "has_email": form.get("has_email", False),
        "has_message": form.get("has_message", False),
        "has_submit": form.get("has_submit", False),
        "action_status": action_status,
        "health": health,
        "issues": issues,
    }


def js_check_pages(forms: list[dict], cap: int = 3) -> list[str]:
    """Pages holding a JS-presumed (empty-action) form, so the browser can verify a real handler."""
    pages: list[str] = []
    for form in forms:
        if form["kind"] == "same_page" and form["page"] not in pages:
            pages.append(form["page"])
    return pages[:cap]


def apply_form_handlers(forms: list[dict], handler_map: dict[str, list[bool]]) -> None:
    """Fold browser handler-detection results back into the form records.

    handler_map: {page_url: [has_handler per form in document order]}. A same-page form with a real
    submit handler is confirmed JavaScript-handled; one with none (a contact form especially) is
    flagged, since submitting it may send nothing.
    """
    for form in forms:
        if form["kind"] != "same_page":
            continue
        handlers = handler_map.get(form["page"])
        idx = form.get("page_index", 0)
        if not handlers or idx >= len(handlers):
            continue
        form["js_checked"] = True
        if handlers[idx]:
            form["kind"] = "js_handled"
            form["target_note"] = "Handled by JavaScript, submit handler verified"
            if form.get("health") == "attention":
                form["health"] = "healthy"
        else:
            if "form_no_submit_handler" not in form["issues"]:
                form["issues"].append("form_no_submit_handler")
            form["target_note"] = "No submit handler detected; the form may send nothing when submitted"
            if form.get("has_email") or form.get("has_message"):
                form["health"] = "broken"


def _form_kind_label(form: dict) -> str:
    if form.get("has_message") or form.get("has_email"):
        return "contact form"
    return "form"


def findings_from_forms(forms: list[dict]) -> list[dict]:
    """Turn broken-form records into scoring findings, framed as the money leak they are."""
    findings: list[dict] = []
    for form in forms:
        label = _form_kind_label(form)
        if "form_action_dead" in form["issues"]:
            findings.append({
                "issue_type": "form_action_dead",
                "confidence": "high",
                "source_url": form["page"],
                "failed_url": form["submit_target"],
                "evidence": f"Your {label} submits to {form['submit_target']}, which returns HTTP "
                            f"{form['action_status']}. Visitor submissions may be silently lost.",
                "revenue_relevant": True,
            })
        elif "form_no_submit_handler" in form["issues"] and (form.get("has_email") or form.get("has_message")):
            findings.append({
                "issue_type": "form_no_submit_handler",
                "confidence": "medium",
                "source_url": form["page"],
                "failed_url": form["page"],
                "evidence": f"Your {label} has no server action and no JavaScript submit handler was "
                            f"detected, so visitor messages may go nowhere.",
                "revenue_relevant": True,
            })
    return findings
