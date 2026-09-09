"""Internal worker: run the revenue-control browser verifier on one CSV, in an isolated process.

The deep-revenue path runs the browser verifier in its own process so a wedged Playwright render can
be hard-killed on the caller's deadline (SIGALRM does not interrupt it - see the browser-hang-backstop
note). This is that process. It imports and calls run_browser_validation directly - it is NOT a
user-facing command; `auditor scan` is the one command for normal use.

Usage (invoked by auditor.v2, not by hand):
  python -m auditor.browser_verify_worker <csv> --output-dir <dir> --timeout <seconds>
"""

from __future__ import annotations

import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditor.browser_verify_worker")
    parser.add_argument("input_csv", type=Path, help="CSV with organization and url columns.")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser


def main() -> int:
    from auditor.browser_verifier import all_organizations, run_browser_validation

    args = build_parser().parse_args()
    run_browser_validation(
        args.input_csv, args.output_dir, all_organizations(args.input_csv), args.timeout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
