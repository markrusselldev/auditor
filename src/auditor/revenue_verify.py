"""Actively verify a revenue form's submit path actually fires - safely.

form_health.py checks a form statically (a dead action URL, a missing JS handler). This goes one
step further: it FILLS and SUBMITS the form in a real browser to confirm the submission genuinely
fires a request, catching a handler that exists but is broken (throws, posts nowhere). It never
delivers a real submission and never fires the site's own analytics:

  - The submit event is preventDefault'd in the CAPTURE phase, so the browser never navigates. No
    delivery, no page unload - and therefore no unload-time analytics beacon (verified: an unload
    `sendBeacon`, the way analytics ships, otherwise slips past request interception).
  - Every outbound request during the submit window is intercepted and ABORTED before it leaves, so
    a JS/AJAX form's request is observed (proving the handler fires, and to which endpoint) without
    being delivered.

The site's own submit handler still runs under our capture-phase preventDefault - only the
browser's default navigation is suppressed - so we still see the request it tried to send.

CONSENT-GATED: this fills and submits, so callers pass own_site=True only for a site the operator
owns (the "this is my site" box). The honest boundary, reflected in the findings: it confirms a
form is wired to a reachable destination; it does not send real data, so it does not confirm the
server accepts and stores the submission (field validation, CSRF, spam filtering).
"""

from __future__ import annotations

from auditor import security
from auditor.ai_visibility import _fetch_text

_DEAD_STATUSES = {404, 410}

# Enumerate forms in document order with the shape we need to pick contact/revenue candidates.
_ENUM_JS = """() => [...document.forms].map((f, i) => {
  const els = [...f.querySelectorAll('input,textarea,select')];
  const skip = ['submit','button','hidden','image','reset','checkbox','radio','file'];
  const typed = els.filter(el => !skip.includes((el.type||'text').toLowerCase()));
  const hasEmail = els.some(el => (el.type||'').toLowerCase()==='email' || /email/i.test(el.name||el.id||''));
  const hasMessage = f.querySelector('textarea') !== null
    || [...f.elements].some(el => /message|comment|inquir/i.test(el.name||el.id||''));
  const hasSubmit = !!f.querySelector('button:not([type=button]),input[type=submit],input[type=image]');
  return { index: i, fieldCount: typed.length, hasEmail, hasMessage, hasSubmit };
})"""

# Capture-phase submit catcher: record where the form would post, then cancel the navigation so the
# browser never unloads. Site handlers (bubble phase) still run, so their request is still made.
_ARM_JS = """() => {
  window.__submits = [];
  document.addEventListener('submit', (e) => {
    const f = e.target;
    let action = '';
    try { action = f.action || ''; } catch (_) {}
    window.__submits.push({ action, method: (f.method||'get').toLowerCase() });
    e.preventDefault();
  }, { capture: true });
}"""


def _is_candidate(form: dict) -> bool:
    """A contact/message/revenue form worth actively testing: interactive and message-bearing."""
    return bool(form["hasSubmit"]) and form["fieldCount"] > 0 and (form["hasEmail"] or form["hasMessage"])


def _endpoint_status(url: str, timeout: float) -> int | str | None:
    if not url or not url.lower().startswith(("http://", "https://")):
        return None
    status, _final, _body = _fetch_text(url, timeout)
    return status


def _clean_action(action: str, page_url: str) -> str:
    """The distinct server endpoint a form posts to, or "" when there is none. An empty or bare
    "#" action, or one that resolves to the page itself, is same-page (JS-handled or nothing), not
    a server endpoint - so if no request fired, the submit did nothing observable."""
    if not action:
        return ""
    base = action.split("#", 1)[0]
    if not base.lower().startswith(("http://", "https://")):
        return ""
    if base.rstrip("/") == page_url.split("#", 1)[0].rstrip("/"):
        return ""
    return base


def _fill_and_submit(page, index: int) -> None:
    form = page.locator("form").nth(index)
    for el in form.locator("input, textarea").all():
        try:
            itype = (el.get_attribute("type") or "text").lower()
        except Exception:
            itype = "text"
        if itype in ("submit", "button", "hidden", "image", "reset", "checkbox", "radio", "file"):
            continue
        value = "test@example.com" if itype == "email" else ("5555550123" if itype == "tel" else "auditor test")
        try:
            el.fill(value, timeout=1000)
        except Exception:
            pass
    submit = form.locator(
        "button:not([type=button]), input[type=submit], input[type=image]"
    ).first
    try:
        submit.click(timeout=1500)
    except Exception:
        pass


def _classify(page_url: str, form: dict, new_requests: list[tuple[str, str]], caught: dict | None,
              timeout: float) -> list[dict]:
    label = "contact form" if (form["hasEmail"] or form["hasMessage"]) else "form"

    # Prefer a POST fired by the submit; else any request; else the form's own resolved action.
    endpoint = ""
    posts = [url for method, url in new_requests if method.upper() == "POST"]
    if posts:
        endpoint = posts[-1]
    elif new_requests:
        endpoint = new_requests[-1][1]
    elif caught:
        endpoint = _clean_action(caught.get("action", ""), page_url)

    if endpoint:
        status = _endpoint_status(endpoint, timeout)
        if isinstance(status, int) and (status in _DEAD_STATUSES or status >= 500):
            return [{
                "issue_type": "revenue_submit_dead_endpoint",
                "confidence": "high",
                "source_url": page_url,
                "failed_url": endpoint,
                "evidence": f"Your {label} submits to {endpoint}, which returns HTTP {status}. "
                            f"Submitting it sends nothing that arrives.",
                "revenue_relevant": True,
            }]
        return []  # fired to a reachable destination: confirmed wired (we do not confirm acceptance)

    # Submit fired no request AND has no server action: the button does nothing.
    return [{
        "issue_type": "revenue_submit_no_request",
        "confidence": "high",
        "source_url": page_url,
        "failed_url": page_url,
        "evidence": f"Your {label}'s submit fires no request and the form has no server action, so "
                    f"visitor submissions likely go nowhere.",
        "revenue_relevant": True,
    }]


def verify_revenue_forms(page_urls: list[str], *, own_site: bool, http_timeout: float = 10.0) -> list[dict]:
    """Fill and submit each candidate revenue form and report broken submit paths.

    own_site MUST be True (the consent gate): this fills and submits forms, so it runs only for a
    site the operator authorized. Returns scoring findings; never delivers a submission.
    """
    if not own_site or not page_urls:
        return []
    from playwright.sync_api import sync_playwright

    findings: list[dict] = []
    pages = list(dict.fromkeys(page_urls))
    with sync_playwright() as pw:
        browser = pw.chromium.launch(**security.browser_launch_kwargs())
        try:
            for url in pages:
                page = browser.new_page()
                outbound: list[tuple[str, str]] = []
                try:
                    page.goto(url, timeout=15000, wait_until="load")
                except Exception:
                    try:
                        page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    except Exception:
                        page.close()
                        continue
                # From here nothing is allowed to leave: record and abort every request. Single
                # param on purpose - Playwright passes (route, request) to a 2-arg handler.
                def _route(route):
                    outbound.append((route.request.method, route.request.url))
                    try:
                        route.abort()
                    except Exception:
                        pass
                page.route("**/*", _route)
                page.evaluate(_ARM_JS)
                try:
                    forms = page.evaluate(_ENUM_JS)
                except Exception:
                    forms = []
                for form in [f for f in forms if _is_candidate(f)]:
                    before = len(outbound)
                    submits_before = page.evaluate("window.__submits.length")
                    _fill_and_submit(page, form["index"])
                    page.wait_for_timeout(500)
                    new_requests = list(outbound[before:])
                    submits = page.evaluate("window.__submits")
                    caught = submits[submits_before] if len(submits) > submits_before else None
                    findings += _classify(url, form, new_requests, caught, http_timeout)
                page.close()
        finally:
            browser.close()
    return findings
