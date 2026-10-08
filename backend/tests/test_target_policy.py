import unittest
from datetime import datetime, timezone

from fastapi import HTTPException

from app.main import (
    require_open_testing_window,
    require_state_changing_permission,
    require_third_party_service_permission,
    testing_window_allows,
)


class StateChangingPermissionTests(unittest.TestCase):
    def test_extended_active_requires_explicit_target_permission(self):
        with self.assertRaises(HTTPException) as raised:
            require_state_changing_permission("extended-active", False)

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("state-changing extended-active tests", raised.exception.detail)

    def test_lower_profiles_and_explicit_permission_are_allowed(self):
        require_state_changing_permission("observe", False)
        require_state_changing_permission("controlled-active", False)
        require_state_changing_permission("extended-active", True)

    def test_workflow_denial_is_explicit(self):
        with self.assertRaises(HTTPException) as raised:
            require_state_changing_permission("extended-active", False, workflow=True)

        self.assertIn("workflow steps", raised.exception.detail)


class ThirdPartyServicePermissionTests(unittest.TestCase):
    def test_provider_adapter_requires_separate_target_permission(self):
        with self.assertRaises(HTTPException) as raised:
            require_third_party_service_permission(True, False)

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("third-party intelligence/provider access", raised.exception.detail)

    def test_local_adapter_and_explicit_permission_are_allowed(self):
        require_third_party_service_permission(False, False)
        require_third_party_service_permission(True, True)

    def test_workflow_denial_is_explicit(self):
        with self.assertRaises(HTTPException) as raised:
            require_third_party_service_permission(True, False, workflow=True)

        self.assertIn("workflow steps", raised.exception.detail)


class TestingWindowTests(unittest.TestCase):
    def test_unrestricted_and_same_day_windows(self):
        noon = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

        self.assertTrue(testing_window_allows(None, None, now=noon))
        self.assertTrue(testing_window_allows(11 * 60, 13 * 60, now=noon))
        self.assertFalse(testing_window_allows(13 * 60, 14 * 60, now=noon))

    def test_overnight_window_wraps_midnight(self):
        late = datetime(2026, 1, 1, 23, 30, tzinfo=timezone.utc)
        early = datetime(2026, 1, 2, 1, 30, tzinfo=timezone.utc)
        noon = datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc)

        self.assertTrue(testing_window_allows(23 * 60, 2 * 60, now=late))
        self.assertTrue(testing_window_allows(23 * 60, 2 * 60, now=early))
        self.assertFalse(testing_window_allows(23 * 60, 2 * 60, now=noon))

    def test_invalid_or_closed_window_is_rejected(self):
        self.assertFalse(testing_window_allows(None, 60))
        self.assertFalse(testing_window_allows(60, 60))
        current = datetime.now(timezone.utc)
        current_minute = current.hour * 60 + current.minute
        closed_start = (current_minute + 60) % 1440
        closed_end = (current_minute + 120) % 1440
        with self.assertRaises(HTTPException) as raised:
            require_open_testing_window(closed_start, closed_end)

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("testing window", raised.exception.detail)


if __name__ == "__main__":
    unittest.main()
