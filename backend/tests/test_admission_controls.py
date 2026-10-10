import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app import main


class FakeCursor:
    def __init__(self, queued):
        self.queued = queued

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, _query):
        return None

    def fetchone(self):
        return (self.queued,)


class FakeConnection:
    def __init__(self, queued):
        self.queued = queued

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return FakeCursor(self.queued)


class FakeQueue:
    def __init__(self, *, queued=0, pause=None):
        self.queued = queued
        self.pause = pause

    def get(self, _key):
        return self.pause

    def llen(self, _key):
        return self.queued


class QueueAdmissionTests(unittest.TestCase):
    def admission(self, *, database_queued=0, redis_queued=0, pause=None, **kwargs):
        queue = FakeQueue(queued=redis_queued, pause=pause)
        with (
            patch.object(main, "queue_client", return_value=queue),
            patch.object(
                main.psycopg,
                "connect",
                return_value=FakeConnection(database_queued),
            ),
            patch.object(main, "MAX_PENDING_RUNS", 5),
        ):
            return main.queue_admission(**kwargs)

    def test_uses_larger_pending_count_and_requested_slots(self):
        result = self.admission(
            database_queued=2,
            redis_queued=3,
            requested_slots=2,
        )

        self.assertTrue(result["allowed"])
        self.assertEqual(result["pending"], 3)
        self.assertEqual(result["available_slots"], 2)
        self.assertEqual(result["requested_slots"], 2)

    def test_capacity_exhaustion_is_rejected_when_enforced(self):
        with self.assertRaises(HTTPException) as raised:
            self.admission(database_queued=4, requested_slots=2, enforce=True)

        self.assertEqual(raised.exception.status_code, 429)
        self.assertIn("capacity", raised.exception.detail)

    def test_pause_state_is_reported_and_enforced(self):
        pause = json.dumps({"paused": True, "reason": "maintenance"})
        result = self.admission(pause=pause)
        self.assertFalse(result["allowed"])
        self.assertTrue(result["paused"])
        self.assertEqual(result["pause"]["reason"], "maintenance")

        with self.assertRaises(HTTPException) as raised:
            self.admission(pause=pause, enforce=True)
        self.assertEqual(raised.exception.status_code, 423)

    def test_invalid_pause_payload_fails_closed(self):
        result = self.admission(pause="not-json")

        self.assertFalse(result["allowed"])
        self.assertTrue(result["paused"])
        self.assertIn("operator review", result["pause"]["reason"])


class StorageAdmissionTests(unittest.TestCase):
    def admission(self, disk, **kwargs):
        with (
            patch.object(main.shutil, "disk_usage", return_value=disk),
            patch.object(main, "MIN_STORAGE_FREE_BYTES", 100),
            patch.object(main, "MAX_STORAGE_USED_PERCENT", 90),
        ):
            return main.storage_admission(**kwargs)

    def test_allows_work_when_both_storage_limits_pass(self):
        result = self.admission(SimpleNamespace(total=1000, used=500, free=500))

        self.assertTrue(result["allowed"])
        self.assertEqual(result["free_bytes"], 500)
        self.assertEqual(result["minimum_free_bytes"], 100)

    def test_minimum_free_reserve_is_enforced(self):
        with self.assertRaises(HTTPException) as raised:
            self.admission(
                SimpleNamespace(total=1000, used=950, free=50),
                enforce=True,
            )

        self.assertEqual(raised.exception.status_code, 507)
        self.assertIn("storage capacity", raised.exception.detail)

    def test_maximum_used_percentage_is_exclusive(self):
        result = self.admission(SimpleNamespace(total=1000, used=900, free=100))

        self.assertFalse(result["allowed"])
        self.assertEqual(result["used_percent"], 90.0)


if __name__ == "__main__":
    unittest.main()
