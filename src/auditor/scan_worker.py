"""Batch worker: run the full audit pipeline (scan_url) on ONE url and print a JSON row.

Runs as its own process so the batch runner can hard-kill a wedged scan without poisoning a shared
browser (auditor.batch explains the concurrency model). This is the exact scan_url the web tool
calls - the batch and the site run identical code.

Usage: python -m auditor.scan_worker <url> [timeout_seconds]
"""

from __future__ import annotations

import json
import socket
import sys

# Bound any stray blocking socket beneath the pipeline's own per-request timeouts.
socket.setdefaulttimeout(45)


def row_from_report(report: dict) -> dict:
    """Flatten a scan_url report to a compact, JSON-serializable batch row."""
    if report.get("unreachable"):
        return {"url": report.get("url"), "business": report.get("business"), "outcome": "unreachable"}
    analytics = report.get("_analytics", {}) or {}
    findings: list[dict] = []
    for category in report.get("categories", []) or []:
        for finding in category.get("findings", []) or []:
            findings.append({
                "category": category.get("name"),
                "issue_type": finding.get("issue_type"),
                "confidence": finding.get("confidence"),
                "revenue_relevant": bool(finding.get("revenue_relevant")),
                "url": finding.get("url"),
                "evidence": (str(finding.get("evidence") or ""))[:500],
            })
    return {
        "url": report.get("url"),
        "business": report.get("business"),
        "overall_score": report.get("overall_score"),
        "overall_grade": analytics.get("overall_grade"),
        "outcome": report.get("scan_outcome"),
        "total_findings": analytics.get("total_findings", len(findings)),
        "findings": findings,
    }


def main() -> int:
    from auditor.scan_one import scan_url  # imported here so --help and tests need no Playwright

    url = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
    try:
        row = row_from_report(scan_url(url, timeout=timeout))
    except Exception as exc:  # noqa: BLE001 - any failure becomes a per-site outcome, never a crash
        row = {"url": url, "outcome": "error", "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(row, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
