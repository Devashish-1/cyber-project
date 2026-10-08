import unittest
from datetime import datetime, timezone

from uuid import UUID

from app.main import build_audit_export, build_defectdojo_report, summarize_adapter_coverage


NOW = datetime(2026, 10, 8, 9, 0, tzinfo=timezone.utc)


def finding(**overrides) -> dict:
    result = {
        "tool_id": "httpx",
        "type": "http-service",
        "title": "HTTP service observed",
        "severity": "medium",
        "asset": "https://authorized.example.test/",
        "details": {"status_code": 200},
        "fingerprint": "a" * 64,
        "review_status": "new",
        "reviewed_at": None,
        "occurrence_count": 2,
        "first_seen": NOW,
        "last_seen": NOW,
    }
    result.update(overrides)
    return result


class DefectDojoExportTests(unittest.TestCase):
    def test_exports_supported_generic_finding_fields(self):
        report = build_defectdojo_report([finding()], include_info=True)
        self.assertEqual(report["type"], "Security Testing Platform")
        exported = report["findings"][0]
        self.assertEqual(exported["severity"], "Medium")
        self.assertEqual(exported["endpoints"], ["https://authorized.example.test/"])
        self.assertEqual(exported["unique_id_from_tool"], "a" * 64)
        self.assertEqual(exported["nb_occurences"], 2)
        self.assertIs(exported["active"], True)

    def test_maps_review_lifecycle_without_quoted_booleans(self):
        statuses = {
            "confirmed": (True, True, False, False, False),
            "false_positive": (False, False, True, False, False),
            "accepted_risk": (True, False, False, True, False),
            "resolved": (False, False, False, False, True),
        }
        for status, expected in statuses.items():
            with self.subTest(status=status):
                exported = build_defectdojo_report([
                    finding(review_status=status, reviewed_at=NOW)
                ], include_info=True)["findings"][0]
                actual = tuple(exported[key] for key in (
                    "active", "verified", "false_p", "risk_accepted", "is_mitigated"
                ))
                self.assertEqual(actual, expected)
                self.assertTrue(all(type(value) is bool for value in actual))
                if status == "resolved":
                    self.assertEqual(exported["mitigated"], str(NOW))

    def test_filters_info_and_does_not_treat_file_paths_as_endpoints(self):
        findings = [
            finding(severity="info"),
            finding(asset="src/app.py", fingerprint="b" * 64),
        ]
        report = build_defectdojo_report(findings)
        self.assertEqual(len(report["findings"]), 1)
        self.assertNotIn("endpoints", report["findings"][0])


class AuditExportTests(unittest.TestCase):
    def test_is_chronological_bounded_and_sanitized(self):
        project_id = UUID("11111111-1111-1111-1111-111111111111")
        rows = [
            (
                UUID("22222222-2222-2222-2222-222222222222"),
                "run.approved",
                "operator",
                "run",
                "run-1",
                {"tool_id": "httpx", "token": "must-not-export"},
                NOW,
            ),
            (
                UUID("33333333-3333-3333-3333-333333333333"),
                "run.cancel_requested",
                "operator",
                "run",
                "run-1",
                {"reason": "operator request"},
                NOW,
            ),
        ]
        report = build_audit_export(project_id, rows, 1)
        self.assertEqual(report["schema"], "security-platform-audit/v1")
        self.assertEqual(report["project_id"], project_id)
        self.assertEqual(report["event_count"], 1)
        self.assertTrue(report["truncated"])
        self.assertEqual(report["events"][0]["event_type"], "run.approved")
        self.assertEqual(report["events"][0]["details"]["token"], "[REDACTED]")


class AdapterCoverageSummaryTests(unittest.TestCase):
    def test_separates_successful_failed_and_unattempted_adapters(self):
        rows = [
            ("httpx", "observe", "succeeded", 2, 2, NOW),
            ("nuclei-reviewed", "controlled-active", "failed", 1, 1, NOW),
            ("not-configured", "observe", "succeeded", 1, 1, NOW),
        ]
        summary = summarize_adapter_coverage(
            rows, ["httpx", "nuclei-reviewed", "testssl", "httpx"]
        )
        self.assertEqual(summary["available_adapters"], ["httpx", "nuclei-reviewed", "testssl"])
        self.assertEqual(summary["attempted_adapters"], ["httpx", "nuclei-reviewed"])
        self.assertEqual(summary["successful_adapters"], ["httpx"])
        self.assertEqual(summary["attempted_without_success"], ["nuclei-reviewed"])
        self.assertEqual(summary["unattempted_adapters"], ["testssl"])
        self.assertEqual(summary["attempted_coverage_percent"], 66.7)
        self.assertEqual(summary["successful_coverage_percent"], 33.3)

    def test_empty_adapter_inventory_is_explicit(self):
        summary = summarize_adapter_coverage([], [])
        self.assertEqual(summary["attempted_coverage_percent"], 0)
        self.assertEqual(summary["successful_coverage_percent"], 0)
        self.assertEqual(summary["unattempted_adapters"], [])


if __name__ == "__main__":
    unittest.main()
