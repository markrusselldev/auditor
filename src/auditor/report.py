"""Scoring (in code) and the report/vision writing (the LLM's one job).

Deterministic code owns every score and every finding. The model only turns the compact JSON into
readable prose and a ranked fix list, and gives one grounded first-impression read of a screenshot.
It is told to ground strictly in what it is given and to say "insufficient information" rather than
invent; it never overrides a deterministic finding. With no key configured, each call returns a
deterministic offline result so the whole report still renders.
"""

from __future__ import annotations

# issue_type -> category. Anything unmatched lands in "Other". Kept as one table on purpose.
_CATEGORY_RULES = (
    ("Mobile experience", ("mobile_",)),
    ("Images & assets", ("broken_image", "rendered_broken_image")),
    ("Links & reachability", ("broken_link", "dead_link", "rendered_page_failure", "redirect",
                              "404", "unreachable", "ssl_certificate_failure",
                              "page_http_failure", "page_navigation_failure", "browser_page_unreachable")),
    ("Revenue paths", ("interface_broken", "failed_iframe", "revenue", "donation", "form")),
    ("Performance", ("slow_", "layout_shift")),
    ("Accessibility", ("accessibility_",)),
    ("Email deliverability", ("dmarc", "spf")),
    ("Security", ("mixed_http",)),
)

# Categories whose findings come from an optional check that can fail to run (no browser render, axe
# not injected, vitals not captured). When that check did not run AND found nothing, the category is
# "not tested", not "clean" - a perfect score there would be misleading, so score/grade go null.
_CHECK_GATED = {"Accessibility": "accessibility", "Performance": "performance",
                "Email deliverability": "deliverability"}

_CONFIDENCE_WEIGHT = {"high": 25, "medium": 12, "low": 5}
_CATEGORY_ORDER = ["AI visibility", "Revenue paths", "Mobile experience", "Images & assets",
                   "Links & reachability", "Performance", "Accessibility", "Email deliverability",
                   "Security", "Other"]


def _category_for(issue_type: str) -> str:
    for name, prefixes in _CATEGORY_RULES:
        if any(issue_type.startswith(p) or p in issue_type for p in prefixes):
            return name
    return "Other"


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _ai_visibility_category(ai: dict) -> dict:
    """Score the AI-visibility checks as deductions from 100. Weights reflect buyer impact."""
    deductions = 0
    items: list[dict] = []
    schema = ai.get("schema_org", {})
    if not schema.get("present"):
        deductions += 25
    items.append({"check": "schema.org", "ok": bool(schema.get("present")), "status": schema.get("status", "")})
    crawlers = ai.get("ai_crawler_access", {})
    if not crawlers.get("present"):
        deductions += 30
    items.append({"check": "AI crawler access", "ok": bool(crawlers.get("present")), "status": crawlers.get("status", "")})
    llms = ai.get("llms_txt", {})
    if not llms.get("present"):
        deductions += 15
    items.append({"check": "llms.txt", "ok": bool(llms.get("present")), "status": llms.get("status", "")})
    score = max(0, 100 - deductions)
    return {"name": "AI visibility", "score": score, "grade": _grade(score), "items": items,
            "tested": True}


def score_categories(findings: list[dict], ai_visibility: dict, checks: dict | None = None) -> list[dict]:
    """One score per category. Findings deduct by confidence; AI visibility by missing checks.

    The same visible element (e.g. one header form) is reported once per page it renders on. Those
    are one issue to a person, so identical findings are collapsed and the score deducts once per
    unique issue, not once per repeat. Findings with different evidence stay separate.
    """
    checks = checks or {}
    buckets: dict[str, list[dict]] = {}
    for finding in findings:
        category = _category_for(str(finding.get("issue_type", "")))
        buckets.setdefault(category, []).append(finding)
    categories = [_ai_visibility_category(ai_visibility)]
    for name in _CATEGORY_ORDER:
        if name == "AI visibility":
            continue
        rows = buckets.get(name, [])
        groups = _collapse(rows)
        deductions = sum(_CONFIDENCE_WEIGHT.get(str(g.get("confidence")), 8) for g in groups)
        score = max(0, 100 - deductions)
        # A gated category with no findings whose check did not run is "not tested", not clean: null
        # its score/grade so it is neither shown as an A nor counted in the overall.
        gate = _CHECK_GATED.get(name)
        not_run = bool(gate) and checks.get(gate) == "no_data" and not groups
        categories.append({
            "name": name,
            "score": None if not_run else score,
            "grade": None if not_run else _grade(score),
            "tested": not not_run,
            "finding_count": len(rows),
            "unique_issue_count": len(groups),
            "findings": groups[:8],
        })
    return categories


def _collapse(findings: list[dict]) -> list[dict]:
    """Merge findings that share (issue_type, evidence) into one brief with an occurrence count."""
    groups: dict[tuple[str, str], dict] = {}
    for finding in findings:
        issue_type = str(finding.get("issue_type", ""))
        evidence = str(finding.get("evidence", "")) or ""
        url = finding.get("failed_url") or finding.get("source_url", "")
        # Key on a prefix so near-identical repeats collapse, but keep the FULL evidence for display
        # (truncating what we show cut a sentence mid-word).
        key = (issue_type, evidence[:200])
        group = groups.get(key)
        if group is None:
            groups[key] = {
                "issue_type": issue_type,
                "confidence": finding.get("confidence", ""),
                "url": url,
                "urls": [url] if url else [],
                "evidence": evidence,
                "count": 1,
                "revenue_relevant": bool(finding.get("revenue_relevant")),
            }
            continue
        group["count"] += 1
        if url and url not in group["urls"] and len(group["urls"]) < 5:
            group["urls"].append(url)
        if _CONFIDENCE_WEIGHT.get(str(finding.get("confidence")), 0) > _CONFIDENCE_WEIGHT.get(str(group["confidence"]), 0):
            group["confidence"] = finding.get("confidence", "")
        group["revenue_relevant"] = group["revenue_relevant"] or bool(finding.get("revenue_relevant"))
    return list(groups.values())


# The overall grade is a WEIGHTED average, not a flat one: the categories that decide whether the
# site actually works for a visitor count double, so a broken form or dead link is not diluted by a
# fistful of clean secondary checks (a broken site should not average out to a C). Weights are the
# product's judgment and are meant to be tuned.
_OVERALL_WEIGHT = {
    "Revenue paths": 2, "Links & reachability": 2, "Mobile experience": 2,
    "Images & assets": 2, "Accessibility": 2,
}


def overall_score(categories: list[dict]) -> int:
    # A "not tested" category (null score) is excluded, so a check that could not run neither inflates
    # nor deflates the overall grade.
    scored = [c for c in categories if c.get("score") is not None]
    if not scored:
        return 100
    total = sum(c["score"] * _OVERALL_WEIGHT.get(c["name"], 1) for c in scored)
    weight = sum(_OVERALL_WEIGHT.get(c["name"], 1) for c in scored)
    return round(total / weight)


def build_compact(business: str, url: str, findings: list[dict], ai_visibility: dict,
                  checks: dict | None = None) -> dict:
    """The COMPACT JSON handed to the model. No raw HTML, only decided facts."""
    categories = score_categories(findings, ai_visibility, checks)
    return {
        "business": business,
        "url": url,
        "overall_score": overall_score(categories),
        "categories": categories,
        "what_ai_says": ai_visibility.get("what_ai_says", []),
        "total_findings": len(findings),
    }


_REPORT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["headline", "summary", "top_fixes"],
    "properties": {
        "headline": {"type": "string", "description": "One plain sentence naming the single biggest issue."},
        "summary": {"type": "string", "description": "2-4 sentences a non-technical owner understands. Ground strictly in the findings; if there is little to report, say so."},
        "top_fixes": {
            "type": "array",
            "description": "3 to 5 prioritized fixes, most impactful first. Only from the provided findings.",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["title", "why_it_matters", "category"],
                "properties": {
                    "title": {"type": "string"},
                    "why_it_matters": {"type": "string"},
                    "category": {"type": "string"},
                },
            },
        },
    },
}

_REPORT_SYSTEM = (
    "You write a short, plain-language website audit for a small-business owner. You are given a "
    "compact JSON of findings that deterministic checks already decided; treat it as ground truth. "
    "Do NOT invent issues, URLs, or facts not present in the JSON. If a category is clean, do not "
    "manufacture problems for it. Prioritize the fixes by real visitor and revenue impact. If there "
    "is little to report, say the site is in good shape rather than padding."
)


def write_report(provider, compact: dict) -> dict:
    """Turn the compact JSON into headline + summary + top fixes. Offline builds it deterministically."""
    import json

    fallback = _deterministic_report(compact)
    return provider.complete_json(
        system=_REPORT_SYSTEM,
        user="Compact findings JSON:\n" + json.dumps(compact, ensure_ascii=False),
        schema=_REPORT_SCHEMA,
        temperature=0.2,
        offline_fallback=fallback,
    )


def _deterministic_report(compact: dict) -> dict:
    """A readable report with no model: rank real findings by weight and name them."""
    ranked: list[tuple[int, dict, str]] = []
    for category in compact["categories"]:
        for finding in category.get("findings", []):
            weight = _CONFIDENCE_WEIGHT.get(str(finding.get("confidence")), 8)
            ranked.append((weight, finding, category["name"]))
        for item in category.get("items", []):
            if not item.get("ok"):
                ranked.append((15, {"issue_type": item["check"], "evidence": item["status"]}, category["name"]))
    ranked.sort(key=lambda t: -t[0])
    fixes = [
        {
            "title": f"Fix: {finding.get('issue_type', 'issue')}",
            "why_it_matters": str(finding.get("evidence") or "Affects how visitors or AI see your site."),
            "category": category,
        }
        for _weight, finding, category in ranked[:5]
    ]
    if fixes:
        headline = f"Top issue: {fixes[0]['title']} ({fixes[0]['category']})."
        summary = (f"This scan found {compact['total_findings']} deterministic finding(s) and scored the "
                   f"site {compact['overall_score']}/100 overall. The prioritized fixes below are ordered "
                   f"by visitor and revenue impact.")
    else:
        headline = "No externally visible failures were detected."
        summary = (f"This scan found no reproducible failures and scored the site "
                   f"{compact['overall_score']}/100 overall. The AI-visibility checks above show where "
                   f"structured data or crawler access could still be improved.")
    return {"headline": headline, "summary": summary, "top_fixes": fixes}


# --- Grounded vision first-impression (AI OPINION, never overrides deterministic findings) ---

_VISION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["insufficient_information", "offer_clarity", "professionalism_trust",
                 "cta_prominence", "glaring_issues", "overall_impression"],
    "properties": {
        "insufficient_information": {"type": "boolean"},
        "offer_clarity": {"type": "string"},
        "professionalism_trust": {"type": "string"},
        "cta_prominence": {"type": "string"},
        "glaring_issues": {"type": "array", "items": {"type": "string"}},
        "overall_impression": {"type": "string"},
    },
}

_VISION_SYSTEM = (
    "You give a brief first-impression read of a website homepage screenshot, as an explicit AI "
    "opinion. Ground everything strictly in what is visible in the image. Do not guess at content "
    "you cannot see, do not invent brand facts, and if the screenshot is blank or unreadable set "
    "insufficient_information to true and leave the assessments empty. Judge only: offer clarity, "
    "professionalism and trust, call-to-action prominence, and any glaring visible issues. "
    "Do NOT transcribe exact phone numbers, email addresses, prices, or other precise strings of "
    "digits or characters, since small OCR errors read as embarrassing mistakes. Refer to such "
    "elements by their presence and prominence instead (for example, 'a phone number and a Get a "
    "quote button are prominent'), never by quoting the literal characters. "
    "If the screenshot is dominated by a blocking interstitial rather than the actual homepage, "
    "such as an age-verification gate, a cookie-consent wall, or a newsletter or promo modal, do "
    "NOT describe the overlay as the site's message or infer the page behind it. Set "
    "insufficient_information to true and, in overall_impression, note that an overlay blocked the "
    "homepage so a first impression could not be assessed."
)


def first_impression(provider, screenshot_png: bytes | None, business: str, url: str) -> dict:
    """One grounded vision read. Returns an unavailable notice offline or with no screenshot."""
    unavailable = {
        "insufficient_information": True,
        "offer_clarity": "",
        "professionalism_trust": "",
        "cta_prominence": "",
        "glaring_issues": [],
        "overall_impression": "A first-impression read was not available for this scan.",
    }
    if not screenshot_png:
        return unavailable
    return provider.complete_json(
        system=_VISION_SYSTEM,
        user=f"Homepage screenshot for {business or url} ({url}). Give your grounded first impression.",
        schema=_VISION_SCHEMA,
        image_png=screenshot_png,
        temperature=0.2,
        offline_fallback=unavailable,
    )
