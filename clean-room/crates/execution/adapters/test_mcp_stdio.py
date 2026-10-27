import subprocess
import threading
import unittest
from unittest.mock import patch
import mcp_stdio


class AdapterTests(unittest.TestCase):
    def test_authority_fields_rejected_without_launching(self):
        with patch.object(mcp_stdio, "run_worker") as run:
            for args in [{"command": "true", "cwd": "/"}, {"command": "true", "policy": "x"},
                         {"command": "true", "env": {}}, {"command": 1}, {}]:
                self.assertEqual(mcp_stdio.execute_tool(args, "exe", "work", "policy"),
                                 mcp_stdio.refused("invalid_request"))
            run.assert_not_called()

    def test_malformed_worker_response_and_raw_stderr_are_withheld(self):
        for body in [b"RAW_FAKE_SECRET", b'{"status":"executed","exit_code":0}',
                     b'{"status":"refused","reason":"RAW_FAKE_SECRET"}']:
            result = subprocess.CompletedProcess([], 0, body, b"RAW_FAKE_SECRET")
            with patch.object(mcp_stdio, "run_worker", return_value=result):
                value = mcp_stdio.execute_tool({"command": "true"}, "exe", "work", "policy")
                self.assertEqual(value, mcp_stdio.refused("execution_unavailable"))
                self.assertNotIn("RAW_FAKE_SECRET", str(value))

    def test_already_cancelled_never_launches_worker(self):
        cancelled = threading.Event()
        cancelled.set()
        with patch.object(mcp_stdio.subprocess, "Popen") as launch:
            response = mcp_stdio.execute_tool({"command": "true"}, "exe", "work", "policy", cancelled)
        self.assertEqual(response, mcp_stdio.refused("execution_unavailable"))
        launch.assert_not_called()

    def test_invalid_trusted_deadline_never_launches_worker(self):
        with patch.object(mcp_stdio, "run_worker") as run:
            for timeout in (0, -1, 191, float("nan"), float("inf")):
                self.assertEqual(mcp_stdio.execute_tool({"command": "true"}, "exe", "work", "policy", timeout=timeout),
                                 mcp_stdio.refused("configuration_unavailable"))
        run.assert_not_called()

    def test_unknown_worker_outcome_is_withheld(self):
        with patch.object(mcp_stdio, "run_worker", return_value=None):
            self.assertEqual(mcp_stdio.execute_tool({"command": "true"}, "exe", "work", "policy"),
                             mcp_stdio.refused("execution_unavailable"))

    def test_refusal_and_nonzero_exit_are_tool_errors(self):
        self.assertTrue(mcp_stdio.tool_result(mcp_stdio.refused("policy_denied"))["isError"])
        self.assertTrue(mcp_stdio.tool_result({"status": "executed", "exit_code": 7, "stdout": "", "stderr": ""})["isError"])
        self.assertFalse(mcp_stdio.tool_result({"status": "executed", "exit_code": 0, "stdout": "safe", "stderr": ""})["isError"])

    def test_boolean_exit_code_is_not_accepted_as_integer(self):
        self.assertFalse(mcp_stdio.valid_response({"status": "executed", "exit_code": False, "stdout": "", "stderr": ""}))


if __name__ == "__main__":
    unittest.main()
