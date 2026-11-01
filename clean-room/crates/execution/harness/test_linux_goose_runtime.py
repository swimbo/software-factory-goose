import base64
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from factory_harness import Denied
from linux_goose_runtime import LinuxWorkerRelay


class Relay:
    def __init__(self):
        self.calls = []

    def exchange(self, body):
        self.calls.append(("inference", body))
        return b"data: [DONE]\n\n"

    def tool(self, name, args):
        self.calls.append((name, args))
        return {"status": "executed"}


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cancelled = threading.Event()
        self.relay = Relay()
        # Protocol/state tests use the host Unix socket implementation; the
        # separate Linux-only relay-path tests exercise real /proc binding.
        with (
            patch("linux_goose_runtime.platform.system", return_value="Linux"),
            patch(
                "linux_goose_runtime.bind_filesystem_socket",
                side_effect=lambda connection, path: connection.bind(str(path)),
            ),
        ):
            self.server = LinuxWorkerRelay(
                Path(self.tmp.name) / "relay.sock",
                worker_uid=2001,
                relay=self.relay,
                deadline=time.monotonic() + 5,
                cancelled=self.cancelled,
            )
        self.addCleanup(self.server.server_close)

    def test_provider_exact_bytes_and_single_dispatch(self):
        self.assertEqual(
            base64.b64decode(
                self.server.dispatch({"type": "inference", "body": {"x": 1}})
            ),
            b"data: [DONE]\n\n",
        )
        self.assertEqual(self.relay.calls, [("inference", {"x": 1})])

    def test_cancel_and_expiry_prevent_dispatch(self):
        self.server.deadline = time.monotonic() - 1
        with self.assertRaises(Denied):
            self.server.dispatch({"type": "inference", "body": {}})
        self.server.deadline = time.monotonic() + 5
        self.cancelled.set()
        with self.assertRaises(Denied):
            self.server.dispatch({"type": "inference", "body": {}})
        self.assertEqual(self.relay.calls, [])

    def test_invalid_tool_shape_precedes_authority(self):
        for request in (
            {"type": "tool", "arguments": {}},
            {"type": "tool", "name": "write_file", "arguments": []},
            {"type": "admin", "name": "reserve", "arguments": {}},
        ):
            with self.assertRaises(Denied):
                self.server.dispatch(request)
        self.assertEqual(self.relay.calls, [])

    def test_typed_call_keeps_logical_authorization_digest(self):
        args = {"path": "solution.py", "content": "pass\n"}
        self.server.dispatch({"type": "tool", "name": "write_file", "arguments": args})
        self.assertEqual(self.relay.calls, [("write_file", args)])

    def test_cancel_can_interrupt_an_inflight_operation(self):
        with self.server.lock:
            self.assertEqual(
                self.server.dispatch({"type": "cancel"}), {"cancelled": True}
            )
        self.assertTrue(self.cancelled.is_set())
        self.assertEqual(self.relay.calls, [])

    def test_worker_and_broker_identity_cannot_alias(self):
        server = None
        try:
            with (
                patch("linux_goose_runtime.platform.system", return_value="Linux"),
                self.assertRaises(Denied),
            ):
                server = LinuxWorkerRelay(
                    Path(self.tmp.name) / "alias.sock",
                    worker_uid=os.geteuid(),
                    relay=self.relay,
                    deadline=time.monotonic() + 5,
                    cancelled=self.cancelled,
                )
        finally:
            if server is not None:
                server.server_close()

    def test_busy_has_no_dispatch(self):
        with self.server.lock:
            with self.assertRaises(Denied):
                self.server.dispatch({"type": "inference", "body": {}})
        self.assertEqual(self.relay.calls, [])


if __name__ == "__main__":
    unittest.main()
