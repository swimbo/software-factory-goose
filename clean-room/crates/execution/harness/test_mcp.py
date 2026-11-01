"""The actual stdio entrypoint must refuse authority overrides and malformed calls."""

import json
import http.server
from pathlib import Path
import select
import subprocess
import sys
import threading
import unittest

from harness_mcp import response_for, FixtureClient
from goose_harness_probe import correct_tool_value


class FakeSession:
    def declarations(self):
        return [
            {
                "name": "run_script",
                "description": "fixture",
                "inputSchema": {"type": "object"},
            }
        ]

    def call(self, name, arguments):
        if name == "run_script" and arguments == {"script": "return 1;"}:
            return {"status": "executed", "output": "1"}
        return {"status": "refused", "reason": "invalid_request"}


class McpContract(unittest.TestCase):
    def test_discovery_does_not_execute_and_refusal_stays_error(self):
        session = FakeSession()
        listed = response_for(
            session, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        self.assertEqual(listed["result"]["tools"][0]["name"], "run_script")
        denied = response_for(
            session,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "run_script",
                    "arguments": {"script": "return 1;", "workdir": "/"},
                },
            },
        )
        self.assertTrue(denied["result"]["isError"])
        self.assertEqual(
            json.loads(denied["result"]["content"][0]["text"])["status"], "refused"
        )
        passed = response_for(
            session,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "run_script", "arguments": {"script": "return 1;"}},
            },
        )
        self.assertFalse(passed["result"]["isError"])

    def test_invalid_protocol_and_unknown_methods_never_echo_input(self):
        for q in [
            {"jsonrpc": "2.0", "id": True, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 4, "method": "private-marker"},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": []},
        ]:
            result = response_for(FakeSession(), q)
            self.assertIn("error", result)
            self.assertNotIn("private-marker", json.dumps(result))

    def test_protocol_metadata_is_not_execution_authority(self):
        value = response_for(
            FakeSession(),
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "run_script",
                    "arguments": {"script": "return 1;"},
                    "_meta": {"progressToken": 1, "workdir": "/"},
                },
            },
        )
        self.assertFalse(value["result"]["isError"])
        huge = response_for(
            FakeSession(), {"jsonrpc": "2.0", "id": "x" * 129, "method": "tools/list"}
        )
        self.assertIn("error", huge)
        self.assertIsNone(huge["id"])


class AdapterLifetime(unittest.TestCase):
    def setUp(self):
        self.started = threading.Event()
        self.cancelled = threading.Event()
        started, cancelled = self.started, self.cancelled

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                json.loads(self.rfile.read(size))
                if self.path == "/factory/list":
                    response = (
                        []
                        if getattr(self.server, "bad_list", False)
                        else [{"name": "run_script"}, {"name": "fetch_tool_schema"}]
                    )
                elif self.path == "/factory/cancel":
                    cancelled.set()
                    response = {"cancelled": True}
                elif self.path == "/factory/call":
                    started.set()
                    cancelled.wait(timeout=3)
                    response = {"status": "refused", "reason": "cancelled"}
                else:
                    self.send_error(404)
                    return
                raw = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.child = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).with_name("harness_mcp.py")),
                "--offline-fixture",
                "--broker-port",
                str(self.server.server_port),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            cwd="/",
        )

    def tearDown(self):
        self.cancelled.set()
        if self.child.poll() is None:
            self.child.terminate()
        self.child.communicate(timeout=4)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def send(self, q):
        self.child.stdin.write(json.dumps(q).encode() + b"\n")
        self.child.stdin.flush()

    def receive(self):
        self.assertTrue(
            select.select([self.child.stdout], [], [], 3)[0],
            "adapter response deadline",
        )
        return json.loads(self.child.stdout.readline())

    def test_real_isolated_stdio_discovers_two_tools(self):
        self.send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in self.receive()["result"]["tools"]}
        self.assertEqual(names, {"run_script", "fetch_tool_schema"})

    def test_busy_then_cancellation_reaches_broker_and_suppresses_result(self):
        self.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "run_script", "arguments": {"script": "return 1;"}},
            }
        )
        self.assertTrue(self.started.wait(timeout=3))
        self.send(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "run_script", "arguments": {"script": "return 2;"}},
            }
        )
        busy = self.receive()
        self.assertEqual(busy["id"], 2)
        self.assertIn("error", busy)
        self.send(
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 1},
            }
        )
        self.assertTrue(self.cancelled.wait(timeout=3))
        self.send({"jsonrpc": "2.0", "id": 9, "method": "ping"})
        self.assertEqual(self.receive(), {"jsonrpc": "2.0", "id": 9, "result": {}})
        self.send(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "run_script", "arguments": {"script": "return 2;"}},
            }
        )
        refused = self.receive()
        self.assertEqual(refused["id"], 10)
        self.assertEqual(
            json.loads(refused["result"]["content"][0]["text"]),
            {"status": "refused", "reason": "attempt_closed"},
        )
        self.child.stdin.close()
        self.child.stdin = None
        out, _ = self.child.communicate(timeout=3)
        self.assertEqual(out, b"")
        self.assertEqual(self.child.returncode, 0)

    def test_eof_cancels_active_broker_work(self):
        self.send(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "run_script", "arguments": {"script": "return 1;"}},
            }
        )
        self.assertTrue(self.started.wait(timeout=3))
        self.child.stdin.close()
        self.child.stdin = None
        out, _ = self.child.communicate(timeout=3)
        self.assertTrue(self.cancelled.is_set())
        self.assertEqual(out, b"")
        self.assertEqual(self.child.returncode, 0)

    def test_malformed_initialize_does_not_orphan_active_call(self):
        self.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "run_script", "arguments": {"script": "return 1;"}},
            }
        )
        self.assertTrue(self.started.wait(timeout=3))
        self.send(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": {"protocolVersion": []},
            }
        )
        self.assertEqual(self.receive()["id"], 2)
        self.child.stdin.close()
        self.child.stdin = None
        out, _ = self.child.communicate(timeout=3)
        self.assertTrue(self.cancelled.is_set())
        self.assertEqual(out, b"")

    def test_exceptional_dispatch_cancels_active_remote_work(self):
        self.server.bad_list = True
        self.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "run_script", "arguments": {"script": "return 1;"}},
            }
        )
        self.assertTrue(self.started.wait(timeout=3))
        self.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        out, error = self.child.communicate(timeout=3)
        self.assertTrue(self.cancelled.is_set())
        self.assertEqual(out, b"")
        self.assertEqual(self.child.returncode, 1)
        self.assertNotIn(b"Traceback", error)


class CompleteResponse(unittest.TestCase):
    def test_truncated_valid_json_never_becomes_success(self):
        class Broken(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                raw = b'{"status":"executed","output":"incomplete"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw) + 25))
                self.end_headers()
                self.wfile.write(raw)
                self.close_connection = True

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Broken)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(ValueError):
                FixtureClient(server.server_port).call(
                    "run_script", {"script": "return 1;"}
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_canary_rejects_corrupt_output_and_missing_or_wrong_schema(self):
        self.assertTrue(correct_tool_value("allowed", [{"output": '"alpha"'}]))
        self.assertFalse(correct_tool_value("allowed", [{"output": '"corrupt"'}]))
        self.assertFalse(correct_tool_value("schema_discovery", [{}]))
        self.assertFalse(
            correct_tool_value("schema_discovery", [{"schema": '{"name":"wrong"}'}])
        )
        self.assertTrue(
            correct_tool_value(
                "schema_discovery",
                [
                    {
                        "schema": json.dumps(
                            {
                                "name": "fixture_read",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {},
                                    "additionalProperties": False,
                                },
                            }
                        )
                    }
                ],
            )
        )


if __name__ == "__main__":
    unittest.main()
