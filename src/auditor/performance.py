"""Performance findings from Core Web Vitals measured in the render.

vision_capture measures LCP (largest contentful paint), CLS (cumulative layout shift), FCP, and
TTFB during its one homepage render. These are LAB numbers from a single test load, not field data
from real users, so the wording says so and confidence stays medium. We flag only genuinely POOR
values (past Google's "poor" threshold), not borderline ones, to avoid noise.
"""

from __future__ import annotations


def performance_findings(web_vitals: dict | None) -> list[dict]:
    if not web_vitals:
        return []
    out: list[dict] = []
    lcp = web_vitals.get("lcp_ms") or 0
    cls = web_vitals.get("cls") or 0
    ttfb = web_vitals.get("ttfb_ms") or 0

    if lcp > 4000:  # Google "poor" is > 4s; "good" is < 2.5s
        out.append(_finding(
            "slow_largest_content",
            f"Your main content took {lcp / 1000:.1f}s to appear in a test load. A visitor waits that "
            f"long before the page looks ready; under 2.5s is the target. Slow first loads lose visitors.",
        ))
    if cls > 0.25:  # Google "poor" is > 0.25; "good" is < 0.1
        out.append(_finding(
            "layout_shift",
            f"Your page moved around as it loaded (a shift score of {cls:.2f}; under 0.1 is stable). "
            f"Content that jumps makes visitors mis-tap and lose their place.",
        ))
    if ttfb > 1800:  # Google "poor" is > 1.8s; "good" is < 0.8s
        out.append(_finding(
            "slow_server_response",
            f"Your server took {ttfb / 1000:.1f}s just to start responding in a test load (under 0.8s "
            f"is good). A slow server delays everything the visitor sees after it.",
        ))
    return out


def _finding(issue_type: str, evidence: str) -> dict:
    return {
        "issue_type": issue_type,
        "confidence": "medium",
        "source_url": "",
        "failed_url": "",
        "evidence": evidence,
        "revenue_relevant": False,
    }
