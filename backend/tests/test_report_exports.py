import unittest
from datetime import datetime, timezone

from app.main import build_defectdojo_report


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


if __name__ == "__main__":
    unittest.main()
