import copy
import unittest
from services.report_guardrails import apply_report_guardrails


def selection(matched=124, unverified=2, mfa=True, vpn=True, auth=True):
    counts = {"MFA": 1, "VPN": 1, "EDR": 1, "Authentication Failures": 4,
              "Authentication Successes": 2} if auth else {"MFA": 1, "VPN": 1, "EDR": 1}
    if not mfa:
        counts.pop("MFA", None)
    if not vpn:
        counts.pop("VPN", None)
    return {
        "events_scanned": matched + unverified,
        "events_sent_to_ai": 12,
        "identity_matched_scanned": matched,
        "identity_unverified_scanned": unverified,
        "aggregated_evidence": {
            "matched_category_counts": counts,
            "unverified_category_counts": {"Firewall": unverified},
            "explicit_mfa_status_counts": {"matched:approved": 1} if mfa else {},
            "explicit_vpn_status_counts": {"matched:connected": 1} if vpn else {},
        }
    }


def report(**patch):
    base = {
        "summary": "Multiple failures, but all events are identity-matched from a new endpoint.",
        "possible_root_cause": "There may have been a password reset or credential leak.",
        "assessment": "Suspicious", "confidence": "Medium", "root_cause_status": "Unconfirmed",
        "evidence": [{"event_ref": "C136", "explanation": "MFA approval suggests user interaction"}],
        "missing_evidence": [
            {"source_type": "MFA", "reason": "MFA device ID", "request": "Export the full MFA challenge log with device ID and timestamp."},
            {"source_type": "VPN", "reason": "VPN client IP", "request": "Export VPN session logs with client IP and session ID."},
        ],
        "recommendations": [],
    }
    base.update(patch)
    return base


class GuardrailTests(unittest.TestCase):
    def evaluate(self, data=None, summary=None, current=None, history=0):
        return apply_report_guardrails(
            report() if data is None else data,
            current if current is not None else [
                {"event_ref": "C136", "event_type": "MFA Challenge", "identity_match": "Matched"}
            ],
            selection() if summary is None else summary,
            "Multiple Failed Logins Followed by Success",
            history,
        )

    def test_corrects_all_matched(self):
        r = self.evaluate()
        self.assertIn("124 saved events", r["summary"])
        self.assertIn("2 remain unverified", r["summary"])
        self.assertNotIn("all events are identity-matched", r["summary"])

    def test_new_endpoint_not_proven(self):
        r = self.evaluate()
        self.assertIn("without a verified historical baseline", r["summary"])

    def test_mfa_caveat(self):
        r = self.evaluate()
        self.assertIn("does not establish", r["evidence"][0]["explanation"])

    def test_existing_mfa_vpn_have_useful_priority(self):
        r = self.evaluate()
        self.assertEqual([x["priority"] for x in r["missing_evidence"]], ["Useful enrichment"]*2)
        self.assertTrue(all("existing SIEM export" in x["request"] for x in r["missing_evidence"]))

    def test_generic_source_reupload_suppressed(self):
        data = report(missing_evidence=[
            {"source_type": "MFA", "reason": "Want everything", "request": "Upload full MFA logs"}
        ])
        self.assertEqual(self.evaluate(data=data)["missing_evidence"], [])

    def test_unresolved_mfa_keeps_focused_request(self):
        s = selection()
        s["aggregated_evidence"]["explicit_mfa_status_counts"] = {}
        data = report(missing_evidence=[
            {"source_type": "MFA", "reason": "Need outcome", "request": "Upload full MFA logs"}
        ])
        r = self.evaluate(data=data, summary=s)
        self.assertEqual(r["missing_evidence"][0]["priority"], "Useful enrichment")
        self.assertIn("specific fields", r["missing_evidence"][0]["request"])

    def test_no_matched_events_forces_inconclusive(self):
        r = self.evaluate(summary=selection(matched=0, unverified=2))
        self.assertEqual(r["assessment"], "Inconclusive")
        self.assertEqual(r["confidence"], "Low")

    def test_no_historical_events_status_remains_unconfirmed(self):
        r = self.evaluate()
        self.assertEqual(r["root_cause_status"], "Unconfirmed")
        self.assertGreater(len(r["review_flags"]), 0)

    def test_duplicate_requests_filtered(self):
        data = report(missing_evidence=[
            {"source_type": "VPN", "reason": "Need IP", "request": "VPN client IP and session ID"},
            {"source_type": "VPN", "reason": "Need device", "request": "VPN device and timestamp"},
        ])
        self.assertEqual(len(self.evaluate(data=data)["missing_evidence"]), 1)

    def test_no_authentication_data_marks_required(self):
        data = report(missing_evidence=[
            {"source_type": "Windows", "reason": "No login outcomes", "request": "Sign-in login timestamps and outcomes"},
        ])
        r = self.evaluate(data=data, summary=selection(auth=False))
        self.assertEqual(r["missing_evidence"][0]["priority"], "Required to resolve")

    def test_does_not_mutate_input(self):
        data = report()
        original = copy.deepcopy(data)
        self.evaluate(data=data)
        self.assertEqual(data, original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
