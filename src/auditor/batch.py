"""Batch-scan a CSV of sites through the full audit pipeline - the same scan_url the web tool runs.

One pipeline, two front doors: the web service calls scan_url per request; this runs scan_url over a
CSV. There is no second, older scan path here - the batch and the site exercise identical code.

Concurrency model (best practice, verified against the Playwright docs): the Playwright sync API is
not thread-safe, so browsers cannot be shared across threads, and a wedged render must be
force-killed rather than signalled (SIGALRM does not interrupt it - see the browser-hang-backstop
note). So each site runs in its OWN subprocess (auditor.scan_worker) with a hard per-site timeout;
on timeout the whole process group is killed, reaping the Chromium children that would otherwise
hold the pipe open. A small thread pool bounds parallelism - the threads only wait on subprocesses,
so no Playwright object ever crosses a thread.
"""

from __future__ import annotations

import csv
import json
import os
import signal
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from auditor.scanner import read_organizations

DEFAULT_WORKER_COMMAND = [sys.executable, "-m", "auditor.scan_worker"]
_KILL_GRACE_SECONDS = 15


def _run_site(worker_command: list[str], org: str, url: str, timeout: float,
              per_site_timeout: float) -> dict:
    proc = subprocess.Popen(
        [*worker_command, url, str(timeout)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True,
    )
    try:
        stdout, _ = proc.communicate(timeout=per_site_timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.communicate(timeout=_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        return {"organization": org, "url": url, "outcome": "timeout"}
    lines = (stdout or "").strip().splitlines()
    if not lines:
        return {"organization": org, "url": url, "outcome": "error", "error": "no worker output"}
    try:
        row = json.loads(lines[-1])
    except json.JSONDecodeError:
        return {"organization": org, "url": url, "outcome": "error", "error": "unparsable worker output"}
    row["organization"] = org
    return row


def run_batch(input_csv: Path, output_dir: Path, *, timeout: float = 20.0,
              per_site_timeout: float = 240.0, workers: int = 3,
              worker_command: list[str] | None = None) -> list[dict]:
    """Scan every (organization, url) in input_csv through the full pipeline; write two CSVs.

    Returns one result dict per site. worker_command is injectable for tests; production uses the
    real scan_worker. Results stream to disk as each site lands, so a long run loses nothing.
    """
    worker_command = worker_command or DEFAULT_WORKER_COMMAND
    organizations = read_organizations(input_csv)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(_run_site, worker_command, org, url, timeout, per_site_timeout): (org, url)
            for org, url in organizations
        }
        for future in as_completed(futures):
            results.append(future.result())
            _write_outputs(results, output_dir)
    return results


def _write_outputs(results: list[dict], output_dir: Path) -> None:
    summary_fields = ["organization", "url", "business", "overall_score", "overall_grade",
                      "outcome", "total_findings"]
    _write_csv(output_dir / "scan-summary.csv", summary_fields,
               [{k: row.get(k, "") for k in summary_fields} for row in results])

    finding_fields = ["organization", "url", "category", "issue_type", "confidence",
                      "revenue_relevant", "failed_url", "evidence"]
    finding_rows: list[dict] = []
    for row in results:
        for finding in row.get("findings", []) or []:
            finding_rows.append({
                "organization": row.get("organization", ""), "url": row.get("url", ""),
                "category": finding.get("category", ""), "issue_type": finding.get("issue_type", ""),
                "confidence": finding.get("confidence", ""),
                "revenue_relevant": finding.get("revenue_relevant", ""),
                "failed_url": finding.get("url", ""), "evidence": finding.get("evidence", ""),
            })
    _write_csv(output_dir / "findings.csv", finding_fields, finding_rows)


def _write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)
