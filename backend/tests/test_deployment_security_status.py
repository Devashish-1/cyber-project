import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.main import read_deployment_security_status


NOW = datetime(2026, 10, 8, 8, 30, tzinfo=timezone.utc)


def service(name: str, **overrides) -> dict:
    result = {
        "service": name,
        "read_only": True,
        "capabilities_dropped": True,
        "no_new_privileges": True,
        "non_root": True,
        "running": True,
        "restart_count": 0,
    }
    result.update(overrides)
    return result


class DeploymentSecurityStatusTests(unittest.TestCase):
    def write_status(self, payload: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "status.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def valid_payload(self) -> dict:
        return {
            "checked_at": (NOW - timedelta(seconds=15)).isoformat(),
            "enforced": True,
            "services": [service("runner"), service("dashboard"), service("api")],
        }

    def test_recomputes_enforcement_from_validated_service_state(self):
        result = read_deployment_security_status(self.write_status(self.valid_payload()), now=NOW)
        self.assertTrue(result["available"])
        self.assertTrue(result["enforced"])
        self.assertTrue(result["fresh"])
        self.assertEqual([item["service"] for item in result["services"]], ["api", "dashboard", "runner"])

    def test_does_not_trust_reported_enforced_value(self):
        payload = self.valid_payload()
        payload["services"][0]["read_only"] = False
        result = read_deployment_security_status(self.write_status(payload), now=NOW)
        self.assertTrue(result["available"])
        self.assertFalse(result["enforced"])

    def test_rejects_duplicate_or_unknown_services(self):
        for services in (
            [service("api"), service("api"), service("runner")],
            [service("api"), service("runner"), service("unknown")],
        ):
            with self.subTest(services=services):
                payload = self.valid_payload()
                payload["services"] = services
                self.assertFalse(
                    read_deployment_security_status(self.write_status(payload), now=NOW)["available"]
                )

    def test_rejects_future_or_malformed_status(self):
        payload = self.valid_payload()
        payload["checked_at"] = (NOW + timedelta(minutes=2)).isoformat()
        self.assertFalse(read_deployment_security_status(self.write_status(payload), now=NOW)["available"])
        payload = self.valid_payload()
        payload["services"][0]["running"] = "true"
        self.assertFalse(read_deployment_security_status(self.write_status(payload), now=NOW)["available"])


if __name__ == "__main__":
    unittest.main()
