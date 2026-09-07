"""Site profile: what the site is built on, who serves it, and how fast it loaded.

Informational context, not pass/fail findings: a buyer sees "you run WordPress behind Cloudflare,
loaded in 1.8s" and immediately trusts the tool knows their site. Detection is signature-based from
the HTML and response headers we already have. Load timing comes from the browser render we already
do. A full performance audit (Core Web Vitals / Lighthouse) is deliberately a v2 concern; this is
one honest load-time number, not that.
"""

from __future__ import annotations

import re

# (label, needle) pairs matched against the lowercased HTML. First hit per group wins.
_CMS_HTML = [
    ("WordPress", "wp-content"), ("WordPress", "wp-json"), ("WordPress", "wp-includes"),
    ("Drupal", "drupal-settings-json"), ("Drupal", "/sites/default/files"),
    ("Joomla", "/media/jui/"), ("Joomla", "com_content"),
    ("Shopify", "cdn.shopify.com"), ("Shopify", "shopify.com/s/"),
    ("Squarespace", "static1.squarespace.com"), ("Squarespace", "squarespace.com"),
    ("Wix", "static.wixstatic.com"), ("Wix", "_wixcssimports"),
    ("Webflow", "data-wf-page"), ("Webflow", ".website-files.com"),
    ("Ghost", "ghost.io"), ("Duda", "irp.cdn-website.com"), ("Framer", "framerusercontent.com"),
]

_FRAMEWORK_HTML = [
    ("Next.js", "__next_data__"), ("Next.js", "/_next/"),
    ("Nuxt", "__nuxt__"), ("Angular", "ng-version"),
    ("Vue", "data-v-"), ("React", "data-reactroot"),
    ("Gatsby", "___gatsby"), ("jQuery", "jquery"),
]

# Header-key -> (label, optional value-substring). Matched case-insensitively.
_CDN_HEADERS = [
    ("cf-ray", ("Cloudflare", "")), ("x-amz-cf-id", ("CloudFront", "")),
    ("x-fastly-request-id", ("Fastly", "")), ("x-vercel-id", ("Vercel", "")),
    ("x-nf-request-id", ("Netlify", "")), ("x-akamai-transformed", ("Akamai", "")),
]


def _generator(html: str) -> str:
    match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
    return match.group(1).strip() if match else ""


def detect_stack(html: str, headers: dict | None = None) -> dict:
    """Return {cms, frameworks, cdn, server, powered_by, generator}. Empty strings when unknown."""
    html_l = (html or "").lower()
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    generator = _generator(html or "")

    cms = ""
    for label, needle in _CMS_HTML:
        if needle in html_l:
            cms = label
            break
    if not cms and generator:
        for name in ("WordPress", "Drupal", "Joomla", "Ghost", "Shopify", "Wix", "Squarespace"):
            if name.lower() in generator.lower():
                cms = name
                break
    if not cms:
        server_blob = (headers.get("x-generator", "") + " " + headers.get("x-powered-by", "")).lower()
        for name in ("drupal", "wordpress", "shopify"):
            if name in server_blob:
                cms = name.capitalize()
                break

    frameworks: list[str] = []
    for label, needle in _FRAMEWORK_HTML:
        if needle in html_l and label not in frameworks:
            frameworks.append(label)

    cdn = ""
    for key, (label, _sub) in _CDN_HEADERS:
        if key in headers:
            cdn = label
            break
    server = headers.get("server", "")
    if not cdn and "cloudflare" in server.lower():
        cdn = "Cloudflare"

    return {
        "cms": cms,
        "frameworks": frameworks,
        "cdn": cdn,
        "server": server,
        "powered_by": headers.get("x-powered-by", ""),
        "generator": generator,
    }


def classify_load(timing: dict | None) -> dict:
    """Turn raw navigation timing (ms) into a labeled load-time summary. Empty when unavailable."""
    if not timing:
        return {}
    load = timing.get("load") or timing.get("dcl") or timing.get("duration") or 0
    load = int(load) if load and load > 0 else 0
    if not load:
        return {}
    label = "fast" if load < 2500 else "moderate" if load < 5000 else "slow"
    return {
        "ttfb_ms": int(timing.get("ttfb") or 0),
        "dcl_ms": int(timing.get("dcl") or 0),
        "load_ms": load,
        "label": label,
    }


def build_site_profile(html: str, headers: dict | None, timing: dict | None) -> dict:
    return {"tech": detect_stack(html, headers), "load": classify_load(timing)}
