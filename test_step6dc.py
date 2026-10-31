"""Step 6D-C offline regression tests. No database, API, or network needed.

Place this file in the fmc-security-tool project root, then run:
    python -m unittest test_step6dc -v
"""

import io
import json
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from services.evidence_profiler import _category, _parse_utc, profile_and_select
from services.incident_patterns import IPCandidateDiscovery, build_ip_pattern_context
from services.streaming_parser import iter_normalized_events


BASE_TS = "2026-10-28T08:00:00+00:00"


def event(number, *, kind="Token Refresh", outcome="Success", ip="192.0.2.25",
          matched=True, mfa="", vpn="", timestamp=BASE_TS):
    """Minimal stored-event double; matches fields read by evidence profiler."""
    return SimpleNamespace(
        id=number,
        timestamp=timestamp,
        event_type=kind,
        outcome=outcome,
        match_status="Matched" if matched else "Unverified",
        source_ip=ip,
        device="TEST-LAPTOP",
        mfa_status=mfa,
        vpn_status=vpn,
        raw_payload="{}",
        upload=SimpleNamespace(source_type="SIEM"),
    )


class RepeatableEvents:
    """Behaves like a re-iterable SQLAlchemy query, without storing all rows."""

    def __init__(self, count):
        self.count = count
        self.passes = 0

    def __iter__(self):
        self.passes += 1
        for number in range(1, self.count + 1):
            failed = number % 7 == 0
            yield event(
                number,
                kind="Windows Failed Login" if failed else "Token Refresh",
                outcome="Failure" if failed else "Success",
            )


class StreamingParserTests(unittest.TestCase):
    def test_csv_records_are_normalized(self):
        payload = (
            "timestamp,email,source_ip,event_type,outcome\n"
            "2026-10-28T08:00:00Z,soc.test@example.com,192.0.2.25,Windows Failed Login,Failure\n"
        ).encode("utf-8")
        rows = list(iter_normalized_events(io.BytesIO(payload), "sample.csv"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["user_email"], "soc.test@example.com")
        self.assertEqual(rows[0]["source_ip"], "192.0.2.25")
        self.assertEqual(rows[0]["outcome"], "Failure")

    def test_json_events_wrapper(self):
        payload = json.dumps({"events": [
            {"email": "soc.test@example.com", "event_type": "Windows Failed Login"},
            {"email": "soc.test@example.com", "event_type": "Token Refresh"},
        ]}).encode("utf-8")
        rows = list(iter_normalized_events(io.BytesIO(payload), "sample.json"))
        self.assertEqual(len(rows), 2)

    def test_csv_extra_columns_are_rejected(self):
        payload = b"email,event_type\nsoc.test@example.com,Login,EXTRA\n"
        with self.assertRaisesRegex(ValueError, "extra or missing columns"):
            list(iter_normalized_events(io.BytesIO(payload), "sample.csv"))

    def test_max_event_limit_rejects_extra_row(self):
        payload = (
            "email,event_type\n"
            + "soc.test@example.com,Token Refresh\n" * 3
        ).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "Maximum 2 events"):
            list(iter_normalized_events(io.BytesIO(payload), "sample.csv", max_events=2))

    def test_invalid_extension_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Supported formats"):
            list(iter_normalized_events(io.BytesIO(b"text"), "sample.exe"))


class EvidenceProfilerTests(unittest.TestCase):
    def test_3500_case_uses_two_passes_and_caps_ai_at_12(self):
        case = RepeatableEvents(3500)
        selected, report = profile_and_select(case, total_in_case=3500, max_selected=12)
        self.assertEqual(case.passes, 2)
        self.assertEqual(report["events_scanned"], 3500)
        self.assertEqual(len(selected), 12)
        self.assertEqual(report["evidence_categories_detected"]["Authentication Failures"], 500)
        self.assertEqual(report["evidence_categories_detected"]["Other"], 3000)
        patterns = report["incident_patterns"]
        self.assertTrue(patterns["available"])
        self.assertEqual(patterns["second_pass_events_scanned"], 3500)
        self.assertEqual(patterns["groups"][0]["saved_events_with_same_ip"], 3500)
        self.assertEqual(patterns["groups"][0]["category_counts"]["Authentication Failures"], 500)
        self.assertIn("repeated_authentication_failures_on_same_ip", patterns["groups"][0]["signals"])
        self.assertNotIn("source_ip", patterns["groups"][0])
        self.assertEqual(report["aggregated_evidence"]["events_summarized"], 3500)

    def test_one_shot_iterator_does_not_fake_second_pass(self):
        one_shot = iter([event(1), event(2, kind="Windows Failed Login", outcome="Failure")])
        selected, report = profile_and_select(one_shot, total_in_case=2)
        self.assertEqual(len(selected), 2)
        self.assertFalse(report["incident_patterns"]["available"])
        self.assertEqual(report["events_scanned"], 2)

    def test_unverified_events_remain_separate(self):
        rows = [event(1), event(2, matched=False), event(3, kind="Windows Failed Login", outcome="Failure")]
        selected, report = profile_and_select(rows, total_in_case=3)
        self.assertEqual(report["identity_matched_scanned"], 2)
        self.assertEqual(report["identity_unverified_scanned"], 1)
        group = report["incident_patterns"]["groups"][0]
        self.assertEqual(group["email_field_matched"], 2)
        self.assertEqual(group["identity_unverified"], 1)
        self.assertEqual(report["aggregated_evidence"]["events_summarized"], 3)
        self.assertEqual(len(selected), 3)

    def test_selection_includes_rare_security_category(self):
        rows = [event(i) for i in range(1, 101)]
        rows.append(event(101, kind="EDR Suspicious Process", outcome="Detected"))
        rows.append(event(102, kind="Windows Failed Login", outcome="Failure"))
        selected, report = profile_and_select(rows, total_in_case=102, max_selected=12)
        self.assertEqual(len(selected), 12)
        self.assertIn(101, {e.id for e in selected})
        self.assertIn(102, {e.id for e in selected})
        self.assertEqual(report["evidence_categories_detected"]["EDR"], 1)

    def test_missing_timezone_is_not_treated_as_utc(self):
        self.assertIsNone(_parse_utc("2026-10-28T08:00:00"))
        self.assertEqual(_parse_utc("2026-10-28T08:00:00Z").tzinfo, timezone.utc)

    def test_invalid_selection_budget_is_rejected(self):
        with self.assertRaises(ValueError):
            profile_and_select([], max_selected=0)
        with self.assertRaises(ValueError):
            profile_and_select([], max_selected=41)


class IncidentPatternTests(unittest.TestCase):
    def test_no_ip_does_not_create_fake_group(self):
        events = [event(1, ip="not-an-ip"), event(2, ip="")]
        selected, report = profile_and_select(events, total_in_case=2)
        self.assertEqual(len(selected), 2)
        self.assertEqual(report["incident_patterns"]["groups"], [])

    def test_candidate_pool_is_bounded(self):
        discovery = IPCandidateDiscovery(capacity=3)
        for number in range(1, 20):
            discovery.observe(
                event(number, ip=f"198.51.100.{number}"),
                "Authentication Failures",
            )
        self.assertLessEqual(len(discovery.candidates()), 3)
        self.assertGreater(discovery.replacements, 0)

    def test_shared_ip_does_not_imply_identity(self):
        events = [
            event(1, kind="Windows Failed Login", outcome="Failure", matched=True),
            event(2, kind="Windows Successful Login", outcome="Success", matched=False),
        ]
        selected, report = profile_and_select(events, total_in_case=2)
        group = report["incident_patterns"]["groups"][0]
        self.assertEqual(group["email_field_matched"], 1)
        self.assertEqual(group["identity_unverified"], 1)
        self.assertIn("failures_and_successes_on_same_ip_order_unverified", group["signals"])
        self.assertIn("does not establish identity", report["incident_patterns"]["interpretation"])
        self.assertEqual({"C1", "C2"}, set(group["selected_event_refs"]))

    def test_empty_case_is_safe(self):
        selected, report = profile_and_select([], total_in_case=0)
        self.assertEqual(selected, [])
        self.assertEqual(report["events_scanned"], 0)
        self.assertEqual(report["incident_patterns"]["groups"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
