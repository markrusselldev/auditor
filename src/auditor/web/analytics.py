"""Privacy-first scan analytics: what we save, and where.

Every field here is coarse and non-identifying by design. We never store the visitor's IP address:
the IP is read once in memory to derive a country and a rough network type (see auditor.geo), then
discarded. We keep no raw User-Agent, no full referrer URL, and nothing that links scans to a person
across sessions. The rest describes the scanned site and our own scan internals -- what it found, what
platform the site runs, which checks ran, how long it took, which AI wrote the report -- so the data
helps improve the tool and the service without being about the visitor.

Format: one JSON record per scan. There is no database server. Locally we append newline-delimited
JSON to a file; in deployed prod each scan is one JSON object in a Cloud Storage bucket (Cloud Run's
disk is ephemeral, so a file there would not survive scale-to-zero). Query it either way with DuckDB
over the JSON (SELECT ... FROM 'scans/*.json') for exact numbers, or hand a batch to the AI for
open-ended patterns. Materialize SQLite from the JSON with one DuckDB command if you ever want it.

Turn it on with AUDITOR_ANALYTICS=local|gcs (default off). Recording is always best-effort: a sink
failure is swallowed so it can never break a scan.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

# Every field a record carries. There is deliberately no "ip" field. Nested objects (finding_counts,
# category_scores, checks, phase_ms) stay as JSON objects, which DuckDB and the AI read natively.
FIELDS = (
    "ts",               # ISO-8601 UTC timestamp of the scan
    "domain",           # registrable domain of the scanned site
    "url_scope",        # "homepage" | "single_page"
    "own_site",         # bool: did the visitor claim they own the site
    "platform",         # scanned site's CMS/tech e.g. "wordpress", or None
    "pages_crawled",    # how many pages this scan actually covered
    "overall_score",    # 0-100
    "overall_grade",    # A-F
    "total_findings",   # count of raw findings before collapse
    "finding_counts",   # {issue_type: count} -- the types and counts of errors
    "category_scores",  # {category: score}
    "checks",           # {check_name: "ok"|"failed"|"skipped"} -- detector health
    "duration_ms",      # how long the scan took, total
    "phase_ms",         # {phase: ms} where the time went, or None
    "outcome",          # "ok" | "error" | "timeout" | "blocked" | "rate_limited"
    "error_kind",       # coarse failure reason, or None
    "llm_provider",     # which model wrote the report e.g. "openai", or None
    "llm_offline",      # bool: the deterministic offline fallback was used
    "country",          # ISO country code from GeoIP, or None (never the IP)
    "network_type",     # "residential" | "hosting" | "unknown" (VPN/proxy heuristic)
    "asn_org",          # network operator name, a curiosity, or None
    "device_class",     # "mobile" | "desktop" | "unknown"
    "browser_family",   # coarse browser name, or None (never the raw User-Agent)
    "language",         # primary Accept-Language subtag e.g. "en", or None
    "referrer_host",    # host of the referrer only, or None (never the full URL)
    "cached",           # bool: served from the passive cache
    "app_version",      # release string, or None
)


def _device_class(user_agent: str | None) -> str:
    if not user_agent:
        return "unknown"
    ua = user_agent.lower()
    if "mobi" in ua or ("android" in ua and "mobile" in ua) or "iphone" in ua or "ipod" in ua:
        return "mobile"
    return "desktop"


def _browser_family(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    ua = user_agent
    if "Edg" in ua:
        return "Edge"
    if "OPR" in ua or "Opera" in ua:
        return "Opera"
    if "Chrome" in ua and "Chromium" not in ua:
        return "Chrome"
    if "Chromium" in ua:
        return "Chromium"
    if "Firefox" in ua:
        return "Firefox"
    if "Safari" in ua:
        return "Safari"
    return "Other"


def _primary_language(accept_language: str | None) -> str | None:
    if not accept_language:
        return None
    tag = accept_language.split(",")[0].split(";")[0].strip()
    primary = tag.split("-")[0].strip().lower()
    return primary or None


def _referrer_host(referrer: str | None) -> str | None:
    if not referrer:
        return None
    try:
        return urlsplit(referrer).hostname or None
    except ValueError:
        return None


def build_record(
    *,
    domain: str,
    url_scope: str,
    own_site: bool,
    overall_score: int,
    overall_grade: str,
    total_findings: int,
    finding_counts: dict,
    category_scores: dict,
    duration_ms: int,
    platform: str | None = None,
    pages_crawled: int | None = None,
    checks: dict | None = None,
    phase_ms: dict | None = None,
    outcome: str = "ok",
    error_kind: str | None = None,
    llm_provider: str | None = None,
    llm_offline: bool | None = None,
    cached: bool = False,
    geo: dict | None = None,
    user_agent: str | None = None,
    referrer: str | None = None,
    accept_language: str | None = None,
    app_version: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Assemble one non-PII analytics record from a finished scan and its request context.

    Raw request signals (user_agent, referrer, accept_language) are reduced here to coarse classes and
    the originals are dropped. geo is the dict from auditor.geo.lookup; the IP that produced it is
    never passed in.
    """
    geo = geo or {}
    when = (now or datetime.now(UTC)).astimezone(UTC)
    return {
        "ts": when.isoformat(),
        "domain": domain or None,
        "url_scope": url_scope,
        "own_site": bool(own_site),
        "platform": platform,
        "pages_crawled": pages_crawled,
        "overall_score": None if overall_score is None else int(overall_score),
        "overall_grade": overall_grade,
        "total_findings": None if total_findings is None else int(total_findings),
        "finding_counts": finding_counts,
        "category_scores": category_scores,
        "checks": checks,
        "duration_ms": int(duration_ms),
        "phase_ms": phase_ms,
        "outcome": outcome,
        "error_kind": error_kind,
        "llm_provider": llm_provider,
        "llm_offline": llm_offline,
        "country": geo.get("country"),
        "network_type": geo.get("network_type", "unknown"),
        "asn_org": geo.get("asn_org"),
        "device_class": _device_class(user_agent),
        "browser_family": _browser_family(user_agent),
        "language": _primary_language(accept_language),
        "referrer_host": _referrer_host(referrer),
        "cached": bool(cached),
        "app_version": app_version,
    }


class NullSink:
    """The default: record nothing."""

    def record(self, record: dict) -> None:  # noqa: D401 - trivial
        pass


class LocalJsonlSink:
    """Append one JSON line per scan to a file. For local use and testing where the disk persists.

    A lock serializes writes across the web server's threads; each record is one line, so DuckDB and
    the AI can read the file directly.
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()

    def record(self, record: dict) -> None:
        line = json.dumps(record, sort_keys=True, ensure_ascii=False)
        with self._lock, open(self.path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


class GcsSink:
    """One JSON object per scan in a Cloud Storage bucket: durable under Cloud Run's ephemeral disk.

    Object key is scans/YYYY/MM/DD/<uuid>.json. Query the prefix with DuckDB or the AI. If
    google-cloud-storage is not installed the sink degrades to a no-op with one warning.
    """

    def __init__(self, bucket: str, prefix: str = "scans", *, bucket_obj=None):
        self.prefix = prefix.strip("/")
        # bucket_obj is injectable so the GCS path can be simulated (a fake client in tests, or the
        # fake-gcs-server emulator, which the SDK reaches on its own via STORAGE_EMULATOR_HOST).
        self._bucket = bucket_obj
        if self._bucket is None:
            try:
                from google.cloud import storage  # optional dependency, only used in deployed prod
                self._bucket = storage.Client().bucket(bucket)
            except Exception as exc:  # missing lib or credentials: do not break the app
                print(f"analytics: GCS sink unavailable ({exc}); recording disabled", file=sys.stderr)

    def record(self, record: dict) -> None:
        if self._bucket is None:
            return
        day = record.get("ts", "")[:10].replace("-", "/") or "unknown"
        key = f"{self.prefix}/{day}/{uuid.uuid4().hex}.json"
        blob = self._bucket.blob(key)
        blob.upload_from_string(
            json.dumps(record, sort_keys=True, ensure_ascii=False), content_type="application/json"
        )


def sink_from_env() -> object:
    """Build the sink named by AUDITOR_ANALYTICS (off|local|gcs). Unknown or unset means NullSink."""
    mode = os.environ.get("AUDITOR_ANALYTICS", "off").strip().lower()
    if mode == "local":
        return LocalJsonlSink(os.environ.get("AUDITOR_ANALYTICS_FILE", "auditor-analytics.jsonl"))
    if mode == "gcs":
        bucket = os.environ.get("AUDITOR_ANALYTICS_BUCKET", "")
        if bucket:
            return GcsSink(bucket)
        print("analytics: AUDITOR_ANALYTICS=gcs but AUDITOR_ANALYTICS_BUCKET unset; disabled",
              file=sys.stderr)
    return NullSink()


def safe_record(sink, record: dict) -> None:
    """Persist best-effort. A sink failure is swallowed so analytics can never break a scan."""
    try:
        sink.record(record)
    except Exception as exc:
        print(f"analytics: record failed ({exc})", file=sys.stderr)
