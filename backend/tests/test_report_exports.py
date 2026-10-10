import unittest
from datetime import datetime, timezone

from pydantic import ValidationError
from uuid import UUID

from app.main import (
    ManualImportDelete,
    ProjectArchive,
    ProjectRestore,
    SourceArtifactDelete,
    TargetDelete,
    SUPERVISED_ADAPTER_EXECUTION_MODES,
    build_audit_export,
    build_defectdojo_report,
    normalize_upload_filename,
    parse_burp_issues,
    serialize_burp_import_row,
    summarize_adapter_coverage,
    summarize_assessment_provenance,
    summarize_coverage_gaps,
    summarize_role_coverage,
    summarize_source_coverage,
    summarize_target_coverage,
)


NOW = datetime(2026, 10, 8, 9, 0, tzinfo=timezone.utc)


class UploadFilenameTests(unittest.TestCase):
    def test_normalizes_browser_and_posix_paths_to_a_basename(self):
        self.assertEqual(
            normalize_upload_filename(r"C:\fakepath\burp-export.xml"),
            "burp-export.xml",
        )
        self.assertEqual(normalize_upload_filename("../../source.zip"), "source.zip")

    def test_rejects_empty_oversized_or_control_character_names(self):
        for filename in ("", "a" * 256 + ".xml", "report\n.xml", "\x7freport.xml"):
            with self.subTest(filename=repr(filename)):
                with self.assertRaisesRegex(ValueError, "filename"):
                    normalize_upload_filename(filename)


class ManualImportDeleteTests(unittest.TestCase):
    def test_requires_exact_destructive_confirmation(self):
        request = ManualImportDelete(
            requested_by="operator", confirmation="DELETE MANUAL IMPORT"
        )
        self.assertEqual(request.confirmation, "DELETE MANUAL IMPORT")

    def test_rejects_ambiguous_confirmation(self):
        with self.assertRaises(ValidationError):
            ManualImportDelete(requested_by="operator", confirmation="delete import")


class SourceArtifactDeleteTests(unittest.TestCase):
    def test_requires_exact_destructive_confirmation(self):
        request = SourceArtifactDelete(
            requested_by="operator", confirmation="DELETE SOURCE ARCHIVE"
        )
        self.assertEqual(request.confirmation, "DELETE SOURCE ARCHIVE")

    def test_rejects_ambiguous_confirmation(self):
        with self.assertRaises(ValidationError):
            SourceArtifactDelete(requested_by="operator", confirmation="delete source")


class TargetDeleteTests(unittest.TestCase):
    def test_requires_exact_destructive_confirmation(self):
        request = TargetDelete(
            requested_by="operator", confirmation="DELETE AUTHORIZED TARGET"
        )
        self.assertEqual(request.confirmation, "DELETE AUTHORIZED TARGET")

    def test_rejects_ambiguous_confirmation(self):
        with self.assertRaises(ValidationError):
            TargetDelete(requested_by="operator", confirmation="delete target")


class ProjectArchiveTests(unittest.TestCase):
    def test_requires_exact_archive_confirmation(self):
        request = ProjectArchive(
            requested_by="operator", confirmation="ARCHIVE PROJECT"
        )
        self.assertEqual(request.confirmation, "ARCHIVE PROJECT")

    def test_rejects_ambiguous_archive_confirmation(self):
        with self.assertRaises(ValidationError):
            ProjectArchive(requested_by="operator", confirmation="archive")

    def test_restore_records_an_operator(self):
        request = ProjectRestore(requested_by="operator")
        self.assertEqual(request.requested_by, "operator")


class CoverageClassificationTests(unittest.TestCase):
    def test_external_service_gated_tools_are_supervised_adapters(self):
        self.assertTrue(
            {"adapter", "approval-gated", "external-service-gated"}.issubset(
                SUPERVISED_ADAPTER_EXECUTION_MODES
            )
        )
        self.assertTrue(
            {"manual", "disabled", "standalone"}.isdisjoint(
                SUPERVISED_ADAPTER_EXECUTION_MODES
            )
        )


class BurpImportTests(unittest.TestCase):
    def test_history_serialization_allowlists_sanitized_metadata(self):
        run_id = UUID("11111111-1111-1111-1111-111111111111")
        target_id = UUID("22222222-2222-2222-2222-222222222222")
        row = (
            run_id, target_id, "https://app.example.test", "succeeded", "operator", NOW,
            {
                "filename": "burp-export.xml", "sha256": "a" * 64,
                "authorization_reference": "approved-session-7", "imported_count": 4,
                "skipped_out_of_scope": 2, "skipped_excluded": 1, "duplicate_count": 3,
                "raw_request": "Authorization: Bearer secret",
                "password": "must-not-leak",
            },
        )
        result = serialize_burp_import_row(row)
        self.assertEqual(result["run_id"], run_id)
        self.assertEqual(result["filename"], "burp-export.xml")
        self.assertEqual(result["imported_count"], 4)
        self.assertNotIn("raw_request", result)
        self.assertNotIn("password", result)
        self.assertNotIn("secret", str(result))

    def test_imports_only_unique_in_scope_non_excluded_metadata(self):
        document = b"""<issues>
          <issue><serialNumber>1</serialNumber><type>123</type><name>Reflected input</name><host>https://app.example.test</host><path>/search?q=secret</path><severity>High</severity><confidence>Certain</confidence><requestresponse><request>Cookie: secret</request></requestresponse></issue>
          <issue><serialNumber>2</serialNumber><type>123</type><name>Reflected input</name><host>https://app.example.test</host><path>/search?q=other</path><severity>High</severity><confidence>Certain</confidence></issue>
          <issue><name>Excluded</name><host>https://app.example.test</host><path>/public/../logout</path><severity>Low</severity></issue>
          <issue><name>Foreign</name><host>https://outside.example.test</host><path>/</path><severity>Critical</severity></issue>
        </issues>"""
        result = parse_burp_issues(
            document, "https://app.example.test", ["app.example.test"], ["/logout"]
        )
        self.assertEqual(len(result["observations"]), 1)
        self.assertEqual(result["duplicate_count"], 1)
        self.assertEqual(result["skipped_excluded"], 1)
        self.assertEqual(result["skipped_out_of_scope"], 1)
        finding = result["observations"][0]
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["asset"], "https://app.example.test/search")
        self.assertFalse(finding["details"]["raw_request_response_retained"])
        self.assertNotIn("secret", str(finding))

    def test_rejects_xml_entity_declarations(self):
        with self.assertRaisesRegex(ValueError, "entity"):
            parse_burp_issues(
                b'<!DOCTYPE issues [<!ENTITY x "unsafe">]><issues/>',
                "https://app.example.test", ["app.example.test"], [],
            )


def finding(**overrides) -> dict:
    result = {
        "tool_id": "httpx",
        "profile": "observe",
        "provenance": "supervised-run",
        "credential_role": None,
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

    def test_includes_authenticated_role_without_credentials(self):
        report = build_defectdojo_report([
            finding(tool_id="playwright", credential_role="administrator")
        ], include_info=True)
        description = report["findings"][0]["description"]
        self.assertIn("Authenticated role: administrator", description)
        self.assertNotIn("password", description.lower())

    def test_identifies_manual_import_provenance(self):
        report = build_defectdojo_report([
            finding(
                tool_id="burp-suite-community", profile="manual-import",
                provenance="manual-import",
            )
        ], include_info=True)
        description = report["findings"][0]["description"]
        self.assertIn("Provenance: manual-import", description)


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


class AssessmentProvenanceSummaryTests(unittest.TestCase):
    def test_keeps_manual_imports_separate_from_supervised_runs(self):
        rows = [
            ("httpx", "observe", "succeeded", 2, 2, NOW),
            ("burp-suite-community", "manual-import", "succeeded", 1, 0, NOW),
        ]
        findings = [
            finding(tool_id="httpx"),
            finding(
                tool_id="burp-suite-community",
                profile="manual-import",
                provenance="manual-import",
            ),
        ]
        summary = summarize_assessment_provenance(rows, findings)
        self.assertEqual(summary["supervised_run_count"], 2)
        self.assertEqual(summary["manual_import_run_count"], 1)
        self.assertEqual(summary["supervised_tools"], ["httpx"])
        self.assertEqual(summary["manual_import_sources"], ["burp-suite-community"])
        self.assertEqual(summary["supervised_finding_count"], 1)
        self.assertEqual(summary["manual_import_finding_count"], 1)


class RoleCoverageSummaryTests(unittest.TestCase):
    def test_reports_tested_successful_and_untested_profiles_without_secrets(self):
        user_id = UUID("44444444-4444-4444-4444-444444444444")
        admin_id = UUID("55555555-5555-5555-5555-555555555555")
        target_id = UUID("66666666-6666-6666-6666-666666666666")
        rows = [
            (user_id, "Standard user", "user", target_id, "https://app.example.test", "succeeded", 2, NOW),
            (user_id, "Standard user", "user", target_id, "https://app.example.test", "failed", 1, NOW),
            (admin_id, "Administrator", "admin", target_id, "https://app.example.test", None, 0, None),
        ]
        coverage = summarize_role_coverage(rows)
        self.assertEqual(coverage["summary"]["configured_profiles"], 2)
        self.assertEqual(coverage["summary"]["tested_profiles"], 1)
        self.assertEqual(coverage["summary"]["successful_profiles"], 1)
        self.assertEqual(coverage["summary"]["untested_profiles"], 1)
        self.assertEqual(coverage["summary"]["tested_coverage_percent"], 50.0)
        profiles = {str(item["id"]): item for item in coverage["profiles"]}
        self.assertEqual(profiles[str(user_id)]["attempted_runs"], 3)
        self.assertEqual(profiles[str(user_id)]["successful_runs"], 2)
        self.assertEqual(profiles[str(admin_id)]["attempted_runs"], 0)
        self.assertNotIn("username", profiles[str(user_id)])
        self.assertNotIn("password", profiles[str(user_id)])

    def test_empty_role_inventory_is_explicit(self):
        coverage = summarize_role_coverage([])
        self.assertEqual(coverage["profiles"], [])
        self.assertEqual(coverage["summary"]["configured_profiles"], 0)
        self.assertEqual(coverage["summary"]["tested_coverage_percent"], 0)


class TargetCoverageSummaryTests(unittest.TestCase):
    def test_keeps_coverage_separate_for_each_target(self):
        first = UUID("77777777-7777-7777-7777-777777777777")
        second = UUID("88888888-8888-8888-8888-888888888888")
        rows = [
            (first, "https://a.example.test", "httpx", "succeeded", 2, NOW),
            (first, "https://a.example.test", "nuclei-reviewed", "failed", 1, NOW),
            (second, "https://b.example.test", None, None, 0, None),
        ]
        coverage = summarize_target_coverage(rows, ["httpx", "nuclei-reviewed"])
        targets = {str(item["id"]): item for item in coverage["targets"]}
        self.assertEqual(targets[str(first)]["attempted_adapters"], ["httpx", "nuclei-reviewed"])
        self.assertEqual(targets[str(first)]["successful_adapters"], ["httpx"])
        self.assertEqual(targets[str(first)]["successful_coverage_percent"], 50.0)
        self.assertEqual(targets[str(second)]["attempted_adapters"], [])
        self.assertEqual(targets[str(second)]["unattempted_adapters"], ["httpx", "nuclei-reviewed"])
        self.assertEqual(targets[str(second)]["attempted_coverage_percent"], 0.0)

    def test_ignores_source_only_or_unknown_adapters(self):
        target_id = UUID("99999999-9999-9999-9999-999999999999")
        coverage = summarize_target_coverage([
            (target_id, "https://app.example.test", "semgrep", "succeeded", 1, NOW),
        ], ["httpx"])
        target = coverage["targets"][0]
        self.assertEqual(target["attempted_adapters"], [])
        self.assertEqual(target["run_count"], 0)

    def test_excludes_adapters_blocked_by_target_policy(self):
        target_id = UUID("99999999-9999-9999-9999-999999999998")
        adapters = {
            "httpx": {"profile": "observe"},
            "dnsrecon": {"profile": "observe"},
            "subfinder": {"profile": "controlled-active", "uses_third_party_services": True},
            "zap-full": {"profile": "extended-active"},
            "k6": {"profile": "load-resilience"},
        }
        rows = [(target_id, "https://app.example.test", None, None, 0, None, False, False, False, None)]
        target = summarize_target_coverage(rows, adapters)["targets"][0]
        self.assertEqual(target["available_adapters"], ["httpx"])
        self.assertEqual(target["available_adapter_count"], 1)
        self.assertEqual(target["policy_gated_adapter_count"], 4)
        self.assertEqual(target["policy_gated_adapters"], ["dnsrecon", "k6", "subfinder", "zap-full"])
        self.assertEqual(target["unattempted_adapters"], ["httpx"])

    def test_includes_adapters_enabled_by_target_policy(self):
        target_id = UUID("99999999-9999-9999-9999-999999999997")
        adapters = {
            "dnsrecon": {"profile": "observe"},
            "subfinder": {"profile": "controlled-active", "uses_third_party_services": True},
            "zap-full": {"profile": "extended-active"},
            "k6": {"profile": "load-resilience"},
        }
        rows = [(target_id, "https://app.example.test", None, None, 0, None, True, True, True, "1.1.1.1:53")]
        target = summarize_target_coverage(rows, adapters)["targets"][0]
        self.assertEqual(target["available_adapter_count"], 4)
        self.assertEqual(target["policy_gated_adapter_count"], 0)
        self.assertEqual(target["unattempted_adapters"], ["dnsrecon", "k6", "subfinder", "zap-full"])


class SourceCoverageSummaryTests(unittest.TestCase):
    def test_keeps_coverage_separate_for_each_source_archive(self):
        first = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        second = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        rows = [
            (first, "app.zip", "1" * 64, "a" * 64, "semgrep", "succeeded", 1, NOW),
            (first, "app.zip", "1" * 64, "a" * 64, "gitleaks", "failed", 1, NOW),
            (second, "api.zip", "2" * 64, None, None, None, 0, None),
        ]
        coverage = summarize_source_coverage(rows, ["gitleaks", "semgrep"])
        artifacts = {str(item["id"]): item for item in coverage["artifacts"]}
        self.assertEqual(artifacts[str(first)]["attempted_adapters"], ["gitleaks", "semgrep"])
        self.assertEqual(artifacts[str(first)]["successful_adapters"], ["semgrep"])
        self.assertEqual(artifacts[str(first)]["successful_coverage_percent"], 50.0)
        self.assertTrue(artifacts[str(first)]["integrity_baseline_ready"])
        self.assertEqual(artifacts[str(first)]["content_sha256"], "a" * 64)
        self.assertEqual(artifacts[str(second)]["attempted_adapters"], [])
        self.assertFalse(artifacts[str(second)]["integrity_baseline_ready"])
        self.assertEqual(artifacts[str(second)]["unattempted_adapters"], ["gitleaks", "semgrep"])

    def test_ignores_target_only_adapters(self):
        artifact_id = UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
        coverage = summarize_source_coverage([
            (artifact_id, "source.zip", "3" * 64, "b" * 64, "httpx", "succeeded", 1, NOW),
        ], ["semgrep"])
        artifact = coverage["artifacts"][0]
        self.assertEqual(artifact["attempted_adapters"], [])
        self.assertEqual(artifact["run_count"], 0)


class CoverageGapSummaryTests(unittest.TestCase):
    def test_aggregates_asset_role_and_adapter_gaps(self):
        result = summarize_coverage_gaps(
            {"unattempted_adapters": ["testssl"], "attempted_without_success": ["nuclei-reviewed"]},
            {"targets": [
                {"id": "t1", "base_url": "https://a.test", "attempted_adapters": [], "successful_adapters": [], "unattempted_adapters": ["httpx"]},
                {"id": "t2", "base_url": "https://b.test", "attempted_adapters": ["httpx"], "successful_adapters": [], "unattempted_adapters": ["subfinder", "testssl"]},
            ]},
            {"artifacts": [
                {"id": "s1", "filename": "app.zip", "sha256": "1" * 64, "integrity_baseline_ready": False, "attempted_adapters": [], "successful_adapters": [], "unattempted_adapters": ["semgrep"]},
            ]},
            {"profiles": [
                {"id": "r1", "name": "Admin", "role_name": "admin", "target": "https://a.test", "attempted_runs": 1, "successful_runs": 0},
            ]},
            ["testssl", "subfinder"],
        )
        self.assertEqual(result["status"], "gaps-present")
        self.assertEqual(result["gap_count"], 10)
        self.assertEqual(result["gaps"]["untested_targets"][0]["id"], "t1")
        self.assertEqual(result["gaps"]["targets_without_success"][0]["id"], "t2")
        self.assertEqual(result["gaps"]["untested_sources"][0]["filename"], "app.zip")
        self.assertEqual(result["gaps"]["sources_without_integrity_baseline"][0]["filename"], "app.zip")
        self.assertEqual(result["gaps"]["roles_without_success"][0]["role_name"], "admin")
        self.assertEqual(result["gaps"]["target_adapter_gaps"][1]["unattempted_adapters"], ["subfinder", "testssl"])
        self.assertEqual(result["gaps"]["source_adapter_gaps"][0]["unattempted_adapters"], ["semgrep"])
        self.assertEqual(result["external_approval_required"], ["subfinder", "testssl"])
        self.assertEqual(result["external_approval_required_count"], 2)

    def test_no_recorded_gaps_does_not_claim_security(self):
        result = summarize_coverage_gaps(
            {"unattempted_adapters": [], "attempted_without_success": []},
            {"targets": []}, {"artifacts": []}, {"profiles": []},
        )
        self.assertEqual(result["status"], "no-recorded-gaps")
        self.assertEqual(result["gap_count"], 0)
        self.assertEqual(result["external_approval_required"], [])
        self.assertIn("does not prove", result["disclaimer"])


if __name__ == "__main__":
    unittest.main()
