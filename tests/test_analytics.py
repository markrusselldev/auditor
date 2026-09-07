import json
import os
import tempfile
import unittest
from datetime import UTC, datetime

from auditor import geo
from auditor.web.analytics import (
    FIELDS,
    GcsSink,
    LocalJsonlSink,
    NullSink,
    build_record,
    safe_record,
    sink_from_env,
)


def _record(**over):
    base = {
        "domain": "example.com", "url_scope": "homepage", "own_site": True,
        "overall_score": 64, "overall_grade": "D", "total_findings": 3,
        "finding_counts": {"broken_image": 2, "missing_spf": 1},
        "category_scores": {"Images & assets": 50}, "duration_ms": 1200,
    }
    base.update(over)
    return build_record(**base)


class BuildRecordTest(unittest.TestCase):
    def test_never_stores_an_ip(self):
        rec = _record(geo={"country": "US", "network_type": "residential", "asn_org": "Comcast"})
        self.assertNotIn("ip", rec)
        # the derived, non-identifying location is kept; the address itself is not
        self.assertEqual(rec["country"], "US")
        self.assertEqual(rec["network_type"], "residential")

    def test_has_exactly_the_schema_fields(self):
        self.assertEqual(set(_record().keys()), set(FIELDS))

    def test_nested_objects_stay_native_json(self):
        rec = _record(checks={"accessibility": "failed"}, phase_ms={"browser": 800})
        self.assertEqual(rec["finding_counts"], {"broken_image": 2, "missing_spf": 1})
        self.assertEqual(rec["checks"], {"accessibility": "failed"})
        self.assertEqual(rec["phase_ms"], {"browser": 800})

    def test_carries_the_tool_improvement_fields(self):
        rec = _record(platform="wordpress", pages_crawled=4, llm_provider="openai", llm_offline=False)
        self.assertEqual(rec["platform"], "wordpress")
        self.assertEqual(rec["pages_crawled"], 4)
        self.assertEqual(rec["llm_provider"], "openai")
        self.assertFalse(rec["llm_offline"])

    def test_reduces_user_agent_to_coarse_classes_only(self):
        ua = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
        rec = _record(user_agent=ua)
        self.assertEqual(rec["device_class"], "mobile")
        self.assertEqual(rec["browser_family"], "Safari")
        self.assertNotIn(ua, rec.values())

    def test_desktop_chrome(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
        rec = _record(user_agent=ua)
        self.assertEqual(rec["device_class"], "desktop")
        self.assertEqual(rec["browser_family"], "Chrome")

    def test_language_is_primary_subtag(self):
        self.assertEqual(_record(accept_language="en-US,en;q=0.9,fr;q=0.8")["language"], "en")
        self.assertIsNone(_record()["language"])

    def test_referrer_is_host_only(self):
        rec = _record(referrer="https://markrussell.io/tools/audit?ref=twitter&id=42")
        self.assertEqual(rec["referrer_host"], "markrussell.io")

    def test_geo_absent_defaults_to_unknown(self):
        rec = _record()
        self.assertIsNone(rec["country"])
        self.assertEqual(rec["network_type"], "unknown")

    def test_tolerates_null_score_for_unreachable_or_error(self):
        rec = build_record(domain="x.com", url_scope="homepage", own_site=False,
                           overall_score=None, overall_grade=None, total_findings=None,
                           finding_counts={}, category_scores={}, duration_ms=0)
        self.assertIsNone(rec["overall_score"])
        self.assertIsNone(rec["total_findings"])
        self.assertIsNone(rec["overall_grade"])


class JsonlSinkTest(unittest.TestCase):
    def test_appends_one_json_line_per_scan(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a.jsonl")
            sink = LocalJsonlSink(path)
            sink.record(_record(domain="acme.org", overall_grade="F"))
            sink.record(_record(domain="two.com"))
            with open(path, encoding="utf-8") as handle:
                lines = [json.loads(line) for line in handle]
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0]["domain"], "acme.org")
            self.assertNotIn("ip", lines[0])


class GcsSinkSimulationTest(unittest.TestCase):
    """Simulate the real Google Cloud path with a fake bucket: prove the object key and payload."""

    class _FakeBlob:
        def __init__(self, key, store):
            self.key = key
            self._store = store

        def upload_from_string(self, data, content_type=None):
            self._store[self.key] = (data, content_type)

    class _FakeBucket:
        def __init__(self):
            self.objects = {}

        def blob(self, key):
            return GcsSinkSimulationTest._FakeBlob(key, self.objects)

    def test_writes_one_json_object_per_scan_with_dated_key(self):
        bucket = self._FakeBucket()
        sink = GcsSink("my-bucket", bucket_obj=bucket)
        sink.record(_record(domain="acme.org", now=datetime(2026, 9, 5, 4, 35, 2, tzinfo=UTC)))
        self.assertEqual(len(bucket.objects), 1)
        key, (data, content_type) = next(iter(bucket.objects.items()))
        # scans/YYYY/MM/DD/<hex>.json
        self.assertRegex(key, r"^scans/2026/09/05/[0-9a-f]{32}\.json$")
        self.assertEqual(content_type, "application/json")
        self.assertEqual(json.loads(data)["domain"], "acme.org")
        self.assertNotIn("ip", json.loads(data))


class SinkSelectionTest(unittest.TestCase):
    def test_default_is_null(self):
        old = os.environ.pop("AUDITOR_ANALYTICS", None)
        try:
            self.assertIsInstance(sink_from_env(), NullSink)
        finally:
            if old is not None:
                os.environ["AUDITOR_ANALYTICS"] = old

    def test_safe_record_swallows_sink_errors(self):
        class Boom:
            def record(self, record):
                raise RuntimeError("disk full")

        safe_record(Boom(), _record())  # must not raise


class GeoTest(unittest.TestCase):
    class _Reader:
        def __init__(self, data):
            self.data = data

        def get(self, ip):
            return self.data.get(ip)

    def test_hosting_org_flags_network_and_keeps_country(self):
        country = self._Reader({"1.2.3.4": {"country": {"iso_code": "DE"}}})
        asn = self._Reader({"1.2.3.4": {"autonomous_system_organization": "Amazon AWS"}})
        out = geo.lookup("1.2.3.4", country_reader=country, asn_reader=asn)
        self.assertEqual(out["country"], "DE")
        self.assertEqual(out["network_type"], "hosting")
        self.assertEqual(out["asn_org"], "Amazon AWS")

    def test_residential_org(self):
        asn = self._Reader({"5.6.7.8": {"autonomous_system_organization": "Comcast Cable"}})
        out = geo.lookup("5.6.7.8", asn_reader=asn)
        self.assertEqual(out["network_type"], "residential")

    def test_no_ip_is_unknown(self):
        out = geo.lookup(None)
        self.assertEqual(out, {"country": None, "network_type": "unknown", "asn_org": None})


if __name__ == "__main__":
    unittest.main()
