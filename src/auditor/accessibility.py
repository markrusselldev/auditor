"""Accessibility findings from axe-core, injected into the rendered page.

axe-core (vendored, MPL-2.0) is the industry-standard rules engine. It runs in the real browser we
already drive and returns the accessibility violations it can detect automatically.

THE HONEST BOUNDARY (kept in the report's disclosure, never dropped): automated checks catch many
common, machine-detectable issues, but they cannot confirm WCAG compliance. Whole categories of
criteria (meaningful alt text, logical focus order, that a screen reader actually makes sense of the
page) can only be verified by a person testing with assistive technology. A clean scan here is a
good sign, NOT a pass. We never claim compliance, and we do not invent a "percent covered" number.

Each violation axe reports is a real, reproducible defect, so the individual findings carry a
confidence set by axe's own impact rating; the coverage caveat lives in the disclosure.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

ACCESSIBILITY_DISCLOSURE = (
    "These are the accessibility problems automated checks can find. A clean result is not a "
    "guarantee that your site meets WCAG; some issues can only be confirmed by a person testing "
    "with assistive technology."
)

# axe impact -> our confidence. The violation is real either way; impact sets how much it matters.
_IMPACT_CONFIDENCE = {"critical": "high", "serious": "high", "moderate": "medium", "minor": "low"}
_IMPACT_ORDER = {"critical": 0, "serious": 1, "moderate": 2, "minor": 3}
_MAX_FINDINGS = 8


@lru_cache(maxsize=1)
def axe_script() -> str:
    """The vendored axe-core source, to inject into a page with add_script_tag(content=...)."""
    return (Path(__file__).parent / "vendor" / "axe.min.js").read_text(encoding="utf-8")


def accessibility_findings(axe_result: dict | None, source_url: str = "") -> list[dict]:
    """Turn an axe.run() result into findings (most severe first, capped)."""
    if not axe_result:
        return []
    violations = sorted(
        axe_result.get("violations") or [],
        key=lambda v: _IMPACT_ORDER.get(v.get("impact"), 4),
    )
    out: list[dict] = []
    for v in violations[:_MAX_FINDINGS]:
        nodes = int(v.get("nodes") or 0)
        out.append({
            "issue_type": "accessibility_" + str(v.get("id", "issue")),
            "confidence": _IMPACT_CONFIDENCE.get(v.get("impact"), "low"),
            "source_url": source_url,
            "failed_url": source_url,
            "evidence": f"{v.get('help', 'Accessibility issue')} "
                        f"(affects {nodes} element{'' if nodes == 1 else 's'}).",
            "revenue_relevant": False,
        })
    return out


def accessibility_summary(axe_result: dict | None) -> dict:
    """The report block: whether the scan ran, how many violations, and the honest disclosure."""
    if not axe_result:
        return {"ran": False, "violation_count": 0, "disclosure": ACCESSIBILITY_DISCLOSURE}
    return {
        "ran": True,
        "violation_count": len(axe_result.get("violations") or []),
        "disclosure": ACCESSIBILITY_DISCLOSURE,
    }
