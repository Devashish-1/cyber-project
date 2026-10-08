import unittest

from app.main import MAX_RUNNER_READINESS_AGE_SECONDS, evaluate_adapter_runtime_readiness


class AdapterRuntimeAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_000.0
        self.configured = {
            "httpx": {"image": "example/httpx@sha256:" + "a" * 64},
            "nuclei-reviewed": {"image": "example/nuclei@sha256:" + "b" * 64},
        }

    def inventory(self, *items, checked_at=None):
        return {
            "checked_at": self.now if checked_at is None else checked_at,
            "adapters": list(items),
        }

    def ready(self, tool_id):
        return {
            "tool_id": tool_id,
            "state": "ready",
            "image": self.configured[tool_id]["image"],
            "image_id": "sha256:" + "c" * 64,
        }

    def test_accepts_fresh_matching_ready_images(self):
        result = evaluate_adapter_runtime_readiness(
            self.inventory(self.ready("httpx"), self.ready("nuclei-reviewed")),
            ["nuclei-reviewed", "httpx"],
            self.configured,
            now=self.now,
        )
        self.assertTrue(result["allowed"])
        self.assertTrue(result["fresh"])
        self.assertEqual(result["unavailable"], [])

    def test_rejects_missing_error_and_image_mismatch(self):
        mismatched = self.ready("httpx")
        mismatched["image"] = "example/httpx@sha256:" + "d" * 64
        result = evaluate_adapter_runtime_readiness(
            self.inventory(mismatched),
            ["httpx", "nuclei-reviewed"],
            self.configured,
            now=self.now,
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["unavailable"], ["httpx", "nuclei-reviewed"])

    def test_rejects_stale_or_future_inventory(self):
        stale = evaluate_adapter_runtime_readiness(
            self.inventory(
                self.ready("httpx"),
                checked_at=self.now - MAX_RUNNER_READINESS_AGE_SECONDS - 1,
            ),
            ["httpx"],
            self.configured,
            now=self.now,
        )
        future = evaluate_adapter_runtime_readiness(
            self.inventory(self.ready("httpx"), checked_at=self.now + 31),
            ["httpx"],
            self.configured,
            now=self.now,
        )
        self.assertFalse(stale["allowed"])
        self.assertFalse(stale["fresh"])
        self.assertFalse(future["allowed"])
        self.assertFalse(future["fresh"])

    def test_rejects_duplicate_or_unidentified_inventory_entries(self):
        ready = self.ready("httpx")
        result = evaluate_adapter_runtime_readiness(
            self.inventory(ready, dict(ready), {"state": "ready"}),
            ["httpx"],
            self.configured,
            now=self.now,
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["unavailable"], ["httpx"])


if __name__ == "__main__":
    unittest.main()
