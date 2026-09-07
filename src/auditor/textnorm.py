"""Normalize scraped text at the boundary, so website smart-typography artifacts never enter our
saved data or the report a visitor sees.

We scrape and PERSIST site text at volume, so a post-hoc detector (like the doc linter) would be a
firehose. Instead we normalize once, right after scrape and before persist: decode HTML entities
first (scraped HTML carries named and numeric character entities: a non-breaking space, an em dash,
a curly apostrophe), then map the smart characters to plain ASCII. The keys are written with chr()
so this source file itself stays ASCII and passes lint-ai-tells (which now also bans dash entities).
"""

from __future__ import annotations

import html

# Smart / non-keyboard characters mapped to their plain ASCII equivalent. Broad on purpose, since
# we ingest raw web HTML: dashes, curly quotes, ellipsis, prime marks, and invisible spaces.
_SMART_MAP = {
    chr(0x2014): "-",    # em dash
    chr(0x2015): "-",    # horizontal bar
    chr(0x2013): "-",    # en dash
    chr(0x2018): "'",    # left single curly quote
    chr(0x2019): "'",    # right single curly quote / apostrophe
    chr(0x201C): '"',    # left double curly quote
    chr(0x201D): '"',    # right double curly quote
    chr(0x2026): "...",  # ellipsis
    chr(0x2032): "'",    # prime
    chr(0x2033): '"',    # double prime
    chr(0x00A0): " ",    # non-breaking space
    chr(0x200B): "",     # zero-width space
    chr(0xFEFF): "",     # zero-width no-break space / BOM
}
_TABLE = str.maketrans(_SMART_MAP)


def normalize_scraped_text(text: str) -> str:
    """Return scraped text with HTML entities decoded and smart characters folded to ASCII."""
    if not text:
        return text
    return html.unescape(text).translate(_TABLE)
