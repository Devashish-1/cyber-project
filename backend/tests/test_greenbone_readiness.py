import json
import unittest
from unittest.mock import patch

from app.main import greenbone_status
from app.runner import GREENBONE_REQUIRED_SERVICES, summarize_greenbone_containers


class FakeContainer:
    def __init__(self, service, status="running", health="healthy", project="greenbone-community"):
        self.labels = {
            "com.docker.compose.service": service,
            "com.docker.compose.project": project,
        }
        self.status = status
        self.attrs = {
            "Config": {"Image": f"registry.community.greenbone.net/community/{service}:stable"},
            "State": {"Status": status, "Health": {"Status": health}},
        }


class GreenboneReadinessTests(unittest.TestCase):
    def test_empty_inventory_is_stopped_and_cannot_submit_scans(self):
        result = summarize_greenbone_containers([], checked_at=1000.0)
        self.assertEqual(result["state"], "stopped")
        self.assertFalse(result["stack_detected"])
        self.assertFalse(result["scan_submission_enabled"])
        self.assertFalse(result["automatic_target_discovery"])

    def test_all_required_services_are_ready(self):
        containers = [FakeContainer(service) for service in GREENBONE_REQUIRED_SERVICES]
        result = summarize_greenbone_containers(containers, checked_at=1000.0)
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["missing_services"], [])
        self.assertEqual(result["unhealthy_services"], [])
        self.assertFalse(result["scan_submission_enabled"])

    def test_unhealthy_service_fails_closed(self):
        containers = [FakeContainer(service) for service in GREENBONE_REQUIRED_SERVICES]
        containers[0].attrs["State"]["Health"]["Status"] = "unhealthy"
        result = summarize_greenbone_containers(containers, checked_at=1000.0)
        self.assertEqual(result["state"], "degraded")
        self.assertTrue(result["unhealthy_services"])
        self.assertFalse(result["scan_submission_enabled"])

    def test_api_returns_only_fresh_sanitized_readiness(self):
        payload = summarize_greenbone_containers([], checked_at=1000.0)
        with patch("app.main.time.time", return_value=1001.0), patch("app.main.queue_client") as queue:
            queue.return_value.get.return_value = json.dumps(payload)
            result = greenbone_status()
        self.assertTrue(result["fresh"])
        self.assertEqual(result["state"], "stopped")
        self.assertFalse(result["scan_submission_enabled"])
        self.assertFalse(result["automatic_target_discovery"])
        self.assertTrue(result["report_import_enabled"])

    def test_api_fails_closed_for_stale_or_invalid_inventory(self):
        with patch("app.main.time.time", return_value=2000.0), patch("app.main.queue_client") as queue:
            queue.return_value.get.return_value = json.dumps({"checked_at": 1000.0, "services": []})
            stale = greenbone_status()
            queue.return_value.get.return_value = "not-json"
            invalid = greenbone_status()
        self.assertEqual(stale["state"], "unknown")
        self.assertEqual(invalid["state"], "unknown")
        self.assertFalse(stale["scan_submission_enabled"])
        self.assertFalse(invalid["scan_submission_enabled"])
    def test_unrelated_compose_services_are_ignored(self):
        result = summarize_greenbone_containers([
            FakeContainer("postgres", project="security-platform"),
        ], checked_at=1000.0)
        self.assertEqual(result["services"], [])
        self.assertEqual(result["state"], "stopped")


if __name__ == "__main__":
    unittest.main()