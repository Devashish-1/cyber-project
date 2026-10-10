import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.main import validate_workflow_tool_ids


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


if __name__ == "__main__":
    unittest.main()
