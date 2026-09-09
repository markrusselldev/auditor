"""Batch runner orchestration: process isolation, hard per-site timeout, and output aggregation.

The full pipeline (scan_url) is covered by test_scan_one; here a fake worker stands in for it so the
batch layer is tested deterministically and fast. The fake prints one JSON row per site, and sleeps
forever for a url containing "hang" so the per-site timeout and process-group kill are exercised.
"""
import csv
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from auditor.batch import run_batch

FAKE_WORKER = (
    "import sys, json, time\n"
    "url = sys.argv[1]\n"
    "if 'hang' in url:\n"
    "    time.sleep(600)\n"
    "print(json.dumps({'url': url, 'business': 'Biz', 'overall_score': 90, 'overall_grade': 'A',\n"
    "                  'outcome': 'clean', 'total_findings': 1,\n"
    "                  'findings': [{'category': 'Images & assets', 'issue_type': 'broken_image',\n"
    "                                'confidence': 'high', 'revenue_relevant': False,\n"
    "                                'url': url + 'x.png', 'evidence': 'missing'}]}))\n"
)
WORKER = [sys.executable, "-c", FAKE_WORKER]


def _csv(directory: Path, rows: list[tuple[str, str]]) -> Path:
    path = directory / "sites.csv"
    with path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("organization", "url"))
        writer.writerows(rows)
    return path


class BatchRunnerTests(unittest.TestCase):
    def test_aggregates_rows_and_writes_findings_and_summary(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = _csv(root, [("One", "https://one.test/"), ("Two", "https://two.test/")])
            rows = run_batch(csv_path, root / "out", workers=2, worker_command=WORKER)
            self.assertEqual({r["organization"] for r in rows}, {"One", "Two"})
            self.assertTrue(all(r.get("overall_score") == 90 for r in rows))
            summary = (root / "out" / "scan-summary.csv").read_text()
            findings = (root / "out" / "findings.csv").read_text()
            self.assertIn("One", summary)
            self.assertIn("broken_image", findings)

    def test_hung_site_is_killed_by_the_per_site_timeout(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = _csv(root, [("Good", "https://good.test/"), ("Bad", "https://hang.test/")])
            started = time.time()
            rows = run_batch(csv_path, root / "out", workers=2, per_site_timeout=2, worker_command=WORKER)
            elapsed = time.time() - started
        by_org = {r["organization"]: r for r in rows}
        self.assertEqual(by_org["Bad"]["outcome"], "timeout")   # hung worker was cut off
        self.assertEqual(by_org["Good"]["overall_score"], 90)   # the healthy site still completed
        self.assertLess(elapsed, 60)  # the 600s sleep was force-killed, not waited out


if __name__ == "__main__":
    unittest.main()
