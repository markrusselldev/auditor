"""Table-stakes page basics: the checks every real audit lists, so the report reads as complete.

These are HYGIENE items, not externally-visible failures. A missing meta description is not a broken
site - it is an SEO/accessibility gap. So they are tagged category "basics" with confidence "info"
and kept OUT of the ranked failure findings; the finding anchor stays reserved for real failures, and
the failure count is never padded with these.

Detection is static and browserless: it parses the HTML the crawl already fetched, so it covers every
crawled page for almost no cost - the same approach as form_health.py.
"""

from __future__ import annotations

from html.parser import HTMLParser


class _BasicsParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._title_parts: list[str] = []
        self._in_title = False
        self.has_meta_description = False
        self.h1_count = 0
        self.img_total = 0
        self.img_missing_alt = 0
        self.has_canonical = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            if a.get("name", "").lower() == "description" and a.get("content", "").strip():
                self.has_meta_description = True
        elif tag == "link":
            if "canonical" in a.get("rel", "").lower().split():
                self.has_canonical = True
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "img":
            self.img_total += 1
            # A present alt (even alt="" for a decorative image) is fine; a MISSING alt attribute is
            # the accessibility gap - a screen reader announces nothing for it.
            if "alt" not in a:
                self.img_missing_alt += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)

    @property
    def title(self) -> str:
        return "".join(self._title_parts).strip()


def _basic(issue_type: str, url: str, evidence: str) -> dict:
    return {
        "issue_type": issue_type,
        "category": "basics",
        "confidence": "info",
        "source_url": url,
        "evidence": evidence,
        "revenue_relevant": False,
    }


def basics_findings(pages: list[tuple[str, str]]) -> list[dict]:
    """Return the table-stakes gaps for each crawled (url, html) page, as 'basics' items."""
    out: list[dict] = []
    for url, html in pages:
        p = _BasicsParser()
        try:
            p.feed(html or "")
        except Exception:
            continue
        if not p.title:
            out.append(_basic("missing_page_title", url,
                              "The page has no title, so search results and the browser tab show no name."))
        if not p.has_meta_description:
            out.append(_basic("missing_meta_description", url,
                              "No meta description, so search engines write their own snippet for you."))
        if p.h1_count == 0:
            out.append(_basic("missing_h1", url,
                              "The page has no main (h1) heading, which weakens structure for readers and search."))
        if p.img_total and p.img_missing_alt:
            out.append(_basic("images_missing_alt", url,
                              f"{p.img_missing_alt} of {p.img_total} images have no alt text, so screen "
                              f"readers announce nothing for them."))
        if not p.has_canonical:
            out.append(_basic("missing_canonical", url,
                              "No canonical link, so duplicate URLs can split your search ranking."))
    return out
