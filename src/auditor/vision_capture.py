"""Capture a clean homepage screenshot for the vision read, dismissing blocking overlays first.

Isolated from the validated detection engine on purpose: the mobile check deliberately treats a
blocking overlay as a finding, so overlays must NOT be stripped globally. This takes a separate
shot used only for the first-impression read, so an age gate or cookie wall does not become the
"homepage" the model describes. Best-effort: if it cannot dismiss the overlay, the vision prompt's
own guard still refuses to describe it.
"""

from __future__ import annotations

import shutil

from auditor import security

# Only act when a genuine blocking overlay is present (a large, visible, fixed/sticky element),
# then click the best-matching dismiss control inside it. Gating on a real overlay avoids clicking
# stray "Enter" or "Continue" links on an ordinary page. Age-affirm and consent labels come first,
# then generic close. Returns what it did so the caller and tests can see it.
_DISMISS_JS = r"""
() => {
  const vw = window.innerWidth, vh = window.innerHeight;
  const visible = el => {
    const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && s.opacity !== '0';
  };
  const overlays = [...document.querySelectorAll('body *')].filter(el => {
    const s = getComputedStyle(el);
    if (s.position !== 'fixed' && s.position !== 'sticky') return false;
    const r = el.getBoundingClientRect();
    if (r.width < vw * 0.5 || r.height < vh * 0.4) return false;
    return visible(el);
  });
  if (!overlays.length) return { clicked: false, overlayPresent: false };
  // Prefer non-attesting dismissal: close/reject/decline BEFORE any affirmation, and never click
  // "accept all cookies" (do not opt the scan into tracking). A simple age "yes/enter" to proceed
  // is acceptable and comes last.
  const patterns = [
    /[×✕✖]/, /\bclose\b/i, /\bdismiss\b/i, /\bno thanks\b/i, /\bmaybe later\b/i,
    /\breject all\b/i, /\breject\b/i, /\bdecline\b/i, /\brefuse\b/i, /\bonly necessary\b/i,
    /\bi am (over )?(21|18)\b/i, /\bover (21|18)\b/i, /\b(21|18)\+/, /\byes,? i am\b/i,
    /\benter( the)?( site)?\b/i, /\bproceed\b/i, /\bcontinue\b/i, /^\s*yes\s*$/i
  ];
  const controls = [];
  for (const root of overlays) {
    controls.push(...root.querySelectorAll('button, a, [role=button], input[type=button], input[type=submit]'));
  }
  const shown = controls.filter(visible);
  const label = el => (el.innerText || el.value || el.getAttribute('aria-label') || '').trim();
  for (const re of patterns) {
    const hit = shown.find(el => re.test(label(el)));
    if (hit) { hit.click(); return { clicked: true, overlayPresent: true, label: label(hit).slice(0, 40) }; }
  }
  return { clicked: false, overlayPresent: true };
}
"""

_OVERLAY_CHECK_JS = r"""
() => {
  const vw = window.innerWidth, vh = window.innerHeight;
  const visible = el => {
    const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && s.opacity !== '0';
  };
  return [...document.querySelectorAll('body *')].some(el => {
    const s = getComputedStyle(el);
    if (s.position !== 'fixed' && s.position !== 'sticky') return false;
    const r = el.getBoundingClientRect();
    return r.width >= vw * 0.5 && r.height >= vh * 0.4 && visible(el);
  });
}
"""

# Classify a blocking interstitial by its text so the scan can report the gate as a finding.
_GATE_DETECT_JS = r"""
() => {
  const vw = window.innerWidth, vh = window.innerHeight;
  const visible = el => {
    const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && s.opacity !== '0';
  };
  const overlay = [...document.querySelectorAll('body *')].find(el => {
    const s = getComputedStyle(el);
    if (s.position !== 'fixed' && s.position !== 'sticky') return false;
    const r = el.getBoundingClientRect();
    return r.width >= vw * 0.5 && r.height >= vh * 0.4 && visible(el);
  });
  if (!overlay) return { present: false, type: '' };
  const text = (overlay.innerText || '').slice(0, 400);
  let type = 'overlay';
  if (/\bage\b|\b21\b|\b18\b|old enough|date of birth|21\+|18\+/i.test(text)) type = 'age gate';
  else if (/cookie|consent|gdpr|\bprivacy\b|tracking/i.test(text)) type = 'cookie/consent wall';
  else if (/subscribe|newsletter|sign ?up|% off|discount|coupon/i.test(text)) type = 'promo/newsletter modal';
  return { present: true, type: type };
}
"""


# Registered BEFORE the page's own scripts (add_init_script) so the observers see every
# largest-contentful-paint and layout-shift from the start. Buffered:true also replays any that
# fired before this ran. Accumulates into window.__vitals for _VITALS_READ_JS to read after load.
_VITALS_INIT_JS = r"""
window.__vitals = { lcp: 0, cls: 0 };
try {
  new PerformanceObserver((l) => {
    for (const e of l.getEntries()) window.__vitals.lcp = e.renderTime || e.loadTime || e.startTime;
  }).observe({ type: 'largest-contentful-paint', buffered: true });
  new PerformanceObserver((l) => {
    for (const e of l.getEntries()) if (!e.hadRecentInput) window.__vitals.cls += e.value;
  }).observe({ type: 'layout-shift', buffered: true });
} catch (e) {}
"""

_VITALS_READ_JS = r"""
() => {
  const v = window.__vitals || { lcp: 0, cls: 0 };
  const fcp = performance.getEntriesByType('paint').find((p) => p.name === 'first-contentful-paint');
  const nav = performance.getEntriesByType('navigation')[0] || {};
  return {
    lcp_ms: Math.round(v.lcp || 0),
    cls: Math.round((v.cls || 0) * 1000) / 1000,
    fcp_ms: Math.round(fcp ? fcp.startTime : 0),
    ttfb_ms: Math.round(nav.responseStart || 0),
  };
}
"""

_TIMING_JS = r"""
() => {
  const nav = performance.getEntriesByType('navigation')[0];
  if (nav) return {
    ttfb: Math.round(nav.responseStart),
    dcl: Math.round(nav.domContentLoadedEventEnd),
    load: Math.round(nav.loadEventEnd),
    duration: Math.round(nav.duration)
  };
  const t = performance.timing; if (!t) return {};
  const s = t.navigationStart;
  return {
    ttfb: t.responseStart - s, dcl: t.domContentLoadedEventEnd - s,
    load: t.loadEventEnd > 0 ? t.loadEventEnd - s : 0, duration: 0
  };
}
"""


def _detect_form_handlers(page) -> list[bool]:
    """Per form (document order): is a real submit handler wired up? Uses CDP event-listener data.

    Checks the form's own submit/click listeners, its submit control's click listeners, an inline
    onsubmit, and document/window-level submit delegation (to avoid false negatives). This is how we
    verify a JavaScript-handled form instead of guessing.
    """
    try:
        cdp = page.context.new_cdp_session(page)
    except Exception:
        cdp = None

    def has_listener(expression: str, types: tuple) -> bool:
        if cdp is None:
            return False
        try:
            result = cdp.send("Runtime.evaluate", {"expression": expression})
            object_id = result.get("result", {}).get("objectId")
            if not object_id:
                return False
            data = cdp.send("DOMDebugger.getEventListeners", {"objectId": object_id})
            return any(entry.get("type") in types for entry in data.get("listeners", []))
        except Exception:
            return False

    delegated = has_listener("document", ("submit",)) or has_listener("window", ("submit",))
    try:
        count = page.evaluate("document.querySelectorAll('form').length")
    except Exception:
        return []
    handlers: list[bool] = []
    for i in range(count):
        form_expr = f"document.querySelectorAll('form')[{i}]"
        button_expr = f"(()=>{{const f={form_expr};return f&&(f.querySelector('[type=submit]')||f.querySelector('button'));}})()"
        try:
            inline = page.evaluate(
                f"(()=>{{const f={form_expr};return !!(f&&(f.getAttribute('onsubmit')||typeof f.onsubmit==='function'));}})()"
            )
        except Exception:
            inline = False
        wired = bool(inline) or delegated or has_listener(form_expr, ("submit", "click")) or has_listener(button_expr, ("click",))
        handlers.append(wired)
    return handlers


def capture_for_vision(url: str, timeout: float = 20.0, form_check_pages: list[str] | None = None) -> tuple[bytes | None, dict]:
    """Return (png_bytes, info). info records dismissal, gate, headers/timing, and form-handler checks.

    form_check_pages: pages holding JS-presumed forms to verify (visited in this same session after
    the screenshot, so no extra browser launch). png is None if the homepage render failed.
    """
    from playwright.sync_api import sync_playwright

    info = {"dismissed": 0, "overlay_remaining": False, "labels": []}
    timeout_ms = round(timeout * 1000)
    with sync_playwright() as pw:
        executable = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
        launch = security.browser_launch_kwargs()
        if executable:
            launch["executable_path"] = executable
        browser = pw.chromium.launch(**launch)
        try:
            context = browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=False)
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            try:
                page.add_init_script(_VITALS_INIT_JS)  # must be registered before navigation
            except Exception:
                pass
            response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            # Response headers reveal the CDN/server for the site profile; captured here to avoid
            # a second request. Best-effort load timing comes from the same render.
            if response is not None:
                info["headers"] = dict(response.headers)
                info["status"] = response.status
            page.wait_for_timeout(700)
            # Detect and classify the gate BEFORE dismissing it, so it can be reported as a finding.
            gate = page.evaluate(_GATE_DETECT_JS)
            # Escape is the most non-attesting dismissal of all: try it first.
            try:
                page.keyboard.press("Escape")
                page.wait_for_timeout(200)
            except Exception:
                pass
            # Two passes: a cookie wall can sit in front of an age gate, or vice versa.
            for _ in range(2):
                result = page.evaluate(_DISMISS_JS)
                if not result.get("clicked"):
                    break
                info["dismissed"] += 1
                if result.get("label"):
                    info["labels"].append(result["label"])
                page.wait_for_timeout(700)
            try:
                page.wait_for_load_state("load", timeout=4000)
            except Exception:
                pass
            info["timing"] = page.evaluate(_TIMING_JS)
            try:
                info["web_vitals"] = page.evaluate(_VITALS_READ_JS)
            except Exception:
                pass
            info["overlay_remaining"] = bool(page.evaluate(_OVERLAY_CHECK_JS))
            info["gate"] = {
                "present": bool(gate.get("present")),
                "type": gate.get("type", ""),
                "dismissed": bool(gate.get("present")) and not info["overlay_remaining"],
            }
            png = page.screenshot(full_page=False, type="png")
            # Accessibility: inject axe-core and collect the violations it can detect. Best-effort;
            # a slow or failed axe run must never sink the scan. Returns only a compact summary
            # (id/impact/help/node-count), never the full DOM node data.
            try:
                from auditor.accessibility import axe_script

                page.add_script_tag(content=axe_script())
                info["axe"] = page.evaluate(
                    """() => axe.run(document, { resultTypes: ['violations'] }).then((r) => ({
                        violations: r.violations.map((v) => ({
                          id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length,
                        })),
                      }))"""
                )
            except Exception:
                pass
            # Reuse this same session to verify JS-handled forms on the pages that have them. The
            # screenshot is already captured, so navigating away now is safe.
            if form_check_pages:
                info["form_handlers"] = {}
                for form_page in form_check_pages[:3]:
                    try:
                        page.goto(form_page, wait_until="domcontentloaded", timeout=timeout_ms)
                        page.wait_for_timeout(500)
                        info["form_handlers"][form_page] = _detect_form_handlers(page)
                    except Exception:
                        continue
            return png, info
        except Exception as exc:
            info["error"] = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
            return None, info
        finally:
            browser.close()
