"""Email-deliverability checks: SPF/DMARC presence from DNS TXT (mocked), findings only for the
certain gaps, DKIM never flagged as missing."""

import unittest
from unittest.mock import patch

from auditor import deliverability


def _fake_doh(records_by_name):
    def _lookup(name, timeout):
        return records_by_name.get(name, [])
    return _lookup


class DeliverabilityTest(unittest.TestCase):
    def test_all_present_no_findings(self):
        records = {
            "acme.com": ["v=spf1 include:_spf.google.com ~all"],
            "_dmarc.acme.com": ["v=DMARC1; p=reject"],
            "google._domainkey.acme.com": ["v=DKIM1; k=rsa; p=MIGf..."],
        }
        with patch.object(deliverability, "_doh_txt", _fake_doh(records)):
            summary = deliverability.check_deliverability("acme.com")
        self.assertTrue(summary["spf"]["present"])
        self.assertTrue(summary["dmarc"]["present"])
        self.assertIs(summary["dkim"]["present"], True)
        self.assertEqual(deliverability.deliverability_findings(summary), [])

    def test_missing_dmarc_and_spf_flagged(self):
        with patch.object(deliverability, "_doh_txt", _fake_doh({})):  # nothing resolves
            summary = deliverability.check_deliverability("acme.com")
        types = {f["issue_type"] for f in deliverability.deliverability_findings(summary)}
        self.assertEqual(types, {"missing_dmarc", "missing_spf"})

    def test_dkim_unknown_is_never_a_finding(self):
        # SPF + enforcing DMARC present, DKIM not found at common selectors -> present is None, and
        # DKIM never produces a finding (its absence is unprovable).
        records = {"acme.com": ["v=spf1 ~all"], "_dmarc.acme.com": ["v=DMARC1; p=reject"]}
        with patch.object(deliverability, "_doh_txt", _fake_doh(records)):
            summary = deliverability.check_deliverability("acme.com")
        self.assertIsNone(summary["dkim"]["present"])
        self.assertEqual(deliverability.deliverability_findings(summary), [])

    def test_dmarc_policy_none_flagged_as_weak(self):
        records = {"acme.com": ["v=spf1 ~all"], "_dmarc.acme.com": ["v=DMARC1; p=none; rua=mailto:x@acme.com"]}
        with patch.object(deliverability, "_doh_txt", _fake_doh(records)):
            summary = deliverability.check_deliverability("acme.com")
        self.assertEqual(summary["dmarc"]["policy"], "none")
        types = {f["issue_type"] for f in deliverability.deliverability_findings(summary)}
        self.assertIn("dmarc_monitoring_only", types)
        self.assertNotIn("missing_dmarc", types)

    def test_dmarc_policy_reject_not_flagged(self):
        records = {"acme.com": ["v=spf1 ~all"], "_dmarc.acme.com": ["v=DMARC1; p=reject"]}
        with patch.object(deliverability, "_doh_txt", _fake_doh(records)):
            summary = deliverability.check_deliverability("acme.com")
        self.assertEqual(summary["dmarc"]["policy"], "reject")
        self.assertEqual(deliverability.deliverability_findings(summary), [])

    def test_empty_domain_not_checked(self):
        summary = deliverability.check_deliverability("")
        self.assertFalse(summary["checked"])
        self.assertEqual(deliverability.deliverability_findings(summary), [])

    def test_findings_do_not_overclaim(self):
        with patch.object(deliverability, "_doh_txt", _fake_doh({})):
            summary = deliverability.check_deliverability("acme.com")
        for f in deliverability.deliverability_findings(summary):
            self.assertIn("not proof", f["evidence"])
            self.assertEqual(f["confidence"], "medium")


if __name__ == "__main__":
    unittest.main()
