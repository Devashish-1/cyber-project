import unittest

from app.runner import effective_timeout_seconds


class EffectiveTimeoutTests(unittest.TestCase):
    def test_target_cap_reduces_adapter_timeout(self):
        self.assertEqual(
            effective_timeout_seconds(
                {"timeout_seconds": 900},
                {"target_max_run_seconds": 300},
            ),
            300,
        )

    def test_target_cannot_extend_adapter_timeout(self):
        self.assertEqual(
            effective_timeout_seconds(
                {"timeout_seconds": 120},
                {"target_max_run_seconds": 900},
            ),
            120,
        )

    def test_source_run_uses_adapter_timeout(self):
        self.assertEqual(
            effective_timeout_seconds({"timeout_seconds": 450}, {}),
            450,
        )

    def test_limits_are_clamped_to_platform_bounds(self):
        self.assertEqual(
            effective_timeout_seconds(
                {"timeout_seconds": 1},
                {"target_max_run_seconds": 1},
            ),
            30,
        )
        self.assertEqual(
            effective_timeout_seconds({"timeout_seconds": 10000}, {}),
            7200,
        )


if __name__ == "__main__":
    unittest.main()
