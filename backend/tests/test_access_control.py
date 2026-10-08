import unittest

from app.main import (
    CONTROL_PLANE_TOKEN,
    CONTROL_PLANE_VIEWER_TOKEN,
    control_plane_role,
    control_plane_role_allows,
)


class AccessControlTests(unittest.TestCase):
    def test_operator_token_has_mutating_access(self):
        self.assertEqual(control_plane_role(CONTROL_PLANE_TOKEN), "operator")
        self.assertTrue(control_plane_role_allows("operator", "POST"))
        self.assertTrue(control_plane_role_allows("operator", "DELETE"))

    def test_viewer_is_read_only_when_configured(self):
        if not CONTROL_PLANE_VIEWER_TOKEN:
            self.skipTest("Viewer token is not configured")
        self.assertEqual(control_plane_role(CONTROL_PLANE_VIEWER_TOKEN), "viewer")
        self.assertTrue(control_plane_role_allows("viewer", "GET"))
        self.assertTrue(control_plane_role_allows("viewer", "HEAD"))
        self.assertFalse(control_plane_role_allows("viewer", "POST"))
        self.assertFalse(control_plane_role_allows("viewer", "PATCH"))
        self.assertFalse(control_plane_role_allows("viewer", "DELETE"))

    def test_unknown_or_empty_token_is_rejected(self):
        self.assertIsNone(control_plane_role(""))
        self.assertIsNone(control_plane_role("x" * 64))


if __name__ == "__main__":
    unittest.main()
