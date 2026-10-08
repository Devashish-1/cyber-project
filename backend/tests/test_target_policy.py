import unittest

from fastapi import HTTPException

from app.main import (
    require_state_changing_permission,
    require_third_party_service_permission,
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


if __name__ == "__main__":
    unittest.main()
