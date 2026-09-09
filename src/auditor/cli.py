from __future__ import annotations

import argparse
from pathlib import Path

from auditor import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Scan organization websites for actionable revenue-path failures.",
    )
    parser.add_argument("--version", action="version", version=f"auditor {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser(
        "scan", help="Scan a CSV of sites through the full audit pipeline (the same one the web tool runs).",
    )
    scan_parser.add_argument("input_csv", type=Path, help="CSV with organization and url columns.")
    scan_parser.add_argument(
        "--output-dir", type=Path, default=Path("data/output"),
        help="Directory for findings.csv and scan-summary.csv.",
    )
    scan_parser.add_argument("--timeout", type=float, default=20.0, help="Per-request timeout in seconds.")
    scan_parser.add_argument(
        "--per-site-timeout", type=float, default=240.0,
        help="Hard wall-clock cap per site; a site exceeding it is killed and recorded as a timeout.",
    )
    scan_parser.add_argument(
        "--workers", type=int, default=3, help="Sites scanned in parallel (each in its own process).",
    )
    # `scan` is the one command for normal use. The older lower-level commands (audit-v2,
    # browser-verify) are archived in auditor.legacy_cli, still runnable via `python -m
    # auditor.legacy_cli <command>`.
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        if args.timeout <= 0:
            parser.error("--timeout must be greater than zero")
        if args.per_site_timeout <= 0:
            parser.error("--per-site-timeout must be greater than zero")
        if args.workers < 1:
            parser.error("--workers must be at least 1")
        from auditor.batch import run_batch
        try:
            results = run_batch(
                args.input_csv, args.output_dir, timeout=args.timeout,
                per_site_timeout=args.per_site_timeout, workers=args.workers,
            )
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))
        finding_count = sum(len(row.get("findings", []) or []) for row in results)
        timed_out = sum(row.get("outcome") == "timeout" for row in results)
        print(
            f"Scanned {len(results)} site(s); found {finding_count} finding(s)"
            + (f"; {timed_out} timed out." if timed_out else ".")
        )
        print(f"Findings: {args.output_dir / 'findings.csv'}")
        print(f"Summary: {args.output_dir / 'scan-summary.csv'}")
