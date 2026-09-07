"""Mixed content: insecure http:// resources referenced by an https page.

Browsers BLOCK active mixed content (scripts, stylesheets, iframes loaded over http) - which breaks
whatever they power - and mark passive mixed content (images, audio, video over http) as "Not
secure". Chromium auto-upgrades or blocks these before a render can observe them, so detection is a
STATIC parse of the page markup, which is what actually carries the insecure reference. Same
static-parse approach as form_health.py / page_basics.py.

Only an explicit http:// URL is mixed content: relative and protocol-relative (//host) URLs inherit
the page's https scheme, and only an https page can HAVE mixed content in the first place.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

# Loaded-over-http these break the page (the browser blocks them) -> high. Everything else is
# passive (an insecure-warning) -> medium.
_ACTIVE = {"script", "iframe", "link"}


class _ResourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.resources: list[tuple[str, str]] = []  # (tag, raw_url)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.resources.append(("script", a["src"]))
        elif tag == "iframe" and a.get("src"):
            self.resources.append(("iframe", a["src"]))
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower().split() and a.get("href"):
            self.resources.append(("link", a["href"]))
        elif tag in ("img", "audio", "video", "source") and a.get("src"):
            self.resources.append((tag, a["src"]))


def mixed_content_findings(pages: list[tuple[str, str]]) -> list[dict]:
    """Flag insecure http:// resources on each crawled https (url, html) page."""
    out: list[dict] = []
    for url, html in pages:
        if urlsplit(url).scheme != "https":
            continue
        parser = _ResourceParser()
        try:
            parser.feed(html or "")
        except Exception:
            continue
        active: list[str] = []
        passive: list[str] = []
        for tag, raw in parser.resources:
            if urlsplit(urljoin(url, raw)).scheme == "http":
                (active if tag in _ACTIVE else passive).append(urljoin(url, raw))
        if active:
            out.append({
                "issue_type": "mixed_http_resource",
                "confidence": "high",
                "source_url": url,
                "failed_url": active[0],
                "evidence": f"This secure page loads {len(active)} script/style resource(s) over "
                            f"insecure http (e.g. {active[0]}); browsers block them, so the page breaks.",
                "revenue_relevant": False,
            })
        if passive:
            out.append({
                "issue_type": "mixed_http_resource",
                "confidence": "medium",
                "source_url": url,
                "failed_url": passive[0],
                "evidence": f"This secure page loads {len(passive)} image/media resource(s) over "
                            f"insecure http (e.g. {passive[0]}); browsers show a 'Not secure' warning.",
                "revenue_relevant": False,
            })
    return out
