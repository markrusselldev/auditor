"""Archived `audit-v2` command, kept runnable but off the primary `auditor` CLI.

`auditor scan` - the full pipeline, the same one the web tool runs - is the one command for normal
use. `audit-v2` predates it and is retired from the main CLI but retained here for diagnostic use;
nothing is deleted (its engine, run_audit_v2, is unchanged and still used by the pipeline and tests).
Run via:

  python -m auditor.legacy_cli audit-v2 <csv> [--output-dir ...] [--no-revenue] [--workers N]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from auditor import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditor.legacy_cli",
        description="Archived lower-level Auditor command (audit-v2).",
    )
    parser.add_argument("--version", action="version", version=f"auditor {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    v2_parser = subparsers.add_parser(
        "audit-v2", help="Run bounded Crawlee inventory and Auditor v2 public-site checks.",
    )
    v2_parser.add_argument("input_csv", type=Path, help="CSV with organization and url columns.")
    v2_parser.add_argument("--output-dir", type=Path, default=Path("data/output/auditor-v2"))
    v2_parser.add_argument("--timeout", type=float, default=20.0)
    v2_parser.add_argument(
        "--no-revenue", dest="deep_revenue", action="store_false", default=True,
        help="Skip the revenue-path verifier. A scan without it is not a defensible outreach scan.",
    )
    v2_parser.add_argument(
        "--workers", type=int, default=2, help="Number of organizations to process in parallel.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "audit-v2":
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


if __name__ == "__main__":
    main()
