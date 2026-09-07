from __future__ import annotations

import argparse
from pathlib import Path

from auditor.scanner import scan_csv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Scan organization websites for actionable revenue-path failures.",
    )
    parser.add_argument("--version", action="version", version="auditor 0.9.0")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Scan organizations from a CSV file.")
    scan_parser.add_argument("input_csv", type=Path, help="CSV with organization and url columns.")
    scan_parser.add_argument(
        "--output-dir", type=Path, default=Path("data/output"),
        help="Directory for findings.csv and scan-summary.csv.",
    )
    scan_parser.add_argument(
        "--resume", action="store_true",
        help="Preserve existing output and skip organizations already in scan-summary.csv.",
    )
    scan_parser.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout in seconds.")
    scan_parser.add_argument(
        "--max-pages", type=int, default=5,
        help="Maximum HTML pages requested per organization, including its homepage.",
    )
    browser_parser = subparsers.add_parser(
        "browser-verify",
        help="Verify visitor-facing revenue controls in a real browser.",
    )
    browser_parser.add_argument("input_csv", type=Path, help="CSV with organization and url columns.")
    browser_parser.add_argument(
        "--output-dir", type=Path, default=Path("data/output/browser-validation"),
        help="Directory for browser evidence, summaries, and screenshots.",
    )
    v2_parser = subparsers.add_parser(
        "audit-v2", help="Run bounded Crawlee inventory and Auditor v2 public-site checks."
    )
    v2_parser.add_argument("input_csv", type=Path, help="CSV with organization and url columns.")
    v2_parser.add_argument("--output-dir", type=Path, default=Path("data/output/auditor-v2"))
    v2_parser.add_argument("--timeout", type=float, default=20.0)
    v2_parser.add_argument(
        "--no-revenue", dest="deep_revenue", action="store_false", default=True,
        help="Skip the revenue-path verifier. A scan without it is not a defensible outreach scan.",
    )
    v2_parser.add_argument(
        "--workers", type=int, default=2,
        help="Number of organizations to process in parallel.",
    )
    browser_parser.add_argument(
        "--timeout", type=float, default=20.0,
        help="Per-page browser action timeout in seconds.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        if args.timeout <= 0:
            parser.error("--timeout must be greater than zero")
        if args.max_pages < 1:
            parser.error("--max-pages must be at least 1")
        try:
            findings, summaries = scan_csv(
                args.input_csv, args.output_dir, args.timeout, args.max_pages, args.resume,
            )
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))
        print(
            f"Scanned {len(summaries)} organization(s); "
            f"found {len(findings)} actionable finding(s)."
        )
        print(f"Findings: {args.output_dir / 'findings.csv'}")
        print(f"Summary: {args.output_dir / 'scan-summary.csv'}")
    elif args.command == "browser-verify":
        if args.timeout <= 0:
            parser.error("--timeout must be greater than zero")
        from auditor.browser_verifier import all_organizations, run_browser_validation
        names = all_organizations(args.input_csv)
        try:
            evidence, summaries = run_browser_validation(
                args.input_csv, args.output_dir, names, args.timeout,
            )
        except KeyboardInterrupt:
            print("Browser verification interrupted; completed evidence flushed.", flush=True)
            raise SystemExit(130) from None
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            parser.error(str(exc))
        confirmed = sum(row.confirmed_broken for row in summaries)
        print(
            f"Browser-reviewed {len(summaries)} organization(s) and "
            f"{len(evidence)} control(s); confirmed {confirmed} broken control(s)."
        )
    elif args.command == "audit-v2":
        if args.timeout <= 0:
            parser.error("--timeout must be greater than zero")
        if args.workers < 1:
            parser.error("--workers must be at least 1")
        from auditor.v2 import run_audit_v2
        try:
            findings, opportunities, coverage, summaries = run_audit_v2(
                args.input_csv, args.output_dir, args.timeout, args.deep_revenue, args.workers,
            )
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            parser.error(str(exc))
        high = sum(row.confidence == "high" for row in findings)
        medium = sum(row.confidence == "medium" for row in findings)
        low = sum(row.confidence == "low" for row in findings)
        print(
            f"Auditor v2 scanned {len(summaries)} organization(s): "
            f"{len(findings)} finding(s) ranked by confidence "
            f"({high} high, {medium} medium, {low} low), "
            f"{len(opportunities)} possible automation opportunities."
        )
