import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.main import RUN_PLANS, validate_workflow_tool_ids


REGISTRY = {
    "tools": {
        "httpx": {"execution": "adapter"},
        "semgrep": {"execution": "adapter"},
    }
}
ADAPTERS = {
    "adapters": {
        "httpx": {"input": "target", "profile": "observe"},
        "semgrep": {"input": "source", "profile": "source-assisted"},
    }
}


class WorkflowInputValidationTests(unittest.TestCase):
    def validate(self, tools, input_type):
        with patch("app.main.load_registry", return_value=REGISTRY), patch(
            "app.main.load_adapters", return_value=ADAPTERS
        ), patch("app.main.RUNNER_IMPLEMENTED_TOOLS", {"httpx", "semgrep"}):
            return validate_workflow_tool_ids(tools, input_type)

    def test_accepts_homogeneous_target_and_source_workflows(self):
        self.assertIn("httpx", self.validate(["httpx"], "target"))
        self.assertIn("semgrep", self.validate(["semgrep"], "source"))

    def test_rejects_cross_input_workflow_steps(self):
        with self.assertRaises(HTTPException) as raised:
            self.validate(["httpx"], "source")
        self.assertIn("Source workflows cannot contain target adapter", raised.exception.detail)

        with self.assertRaises(HTTPException) as raised:
            self.validate(["semgrep"], "target")
        self.assertIn("Target workflows cannot contain source adapter", raised.exception.detail)

    def test_rejects_mixed_and_duplicate_steps(self):
        with self.assertRaises(HTTPException):
            self.validate(["httpx", "semgrep"], "target")
        with self.assertRaises(HTTPException):
            self.validate(["semgrep", "semgrep"], "source")

    def test_deep_web_plan_has_broad_ordered_coverage(self):
        plan = RUN_PLANS["deep-web-authorized"]
        self.assertGreaterEqual(len(plan), 15)
        self.assertEqual(len(plan), len(set(plan)))
        self.assertTrue({"httpx", "whatweb", "testssl", "katana", "nuclei-reviewed", "dalfox", "zap-full"}.issubset(plan))
        self.assertLess(plan.index("zap-baseline"), plan.index("zap-full"))
        self.assertEqual(plan[-1], "zap-full")


if __name__ == "__main__":
    unittest.main()
