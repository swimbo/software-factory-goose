"""Root gateway process checks; synthetic proc files do not prove Linux custody."""

import contextlib
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import linux_supervisor as root
import gateway_custody as custody


class GatewayPeerTests(unittest.TestCase):
    def test_broker_proc_namespace_and_missing_peer_fail_closed(self):
        with (
            patch.object(
                custody.Path, "read_text", return_value=f"{os.getpid()} (public)"
            ),
            patch.object(root, "_ticks", return_value=99),
        ):
            self.assertEqual(custody.gateway_peer_ticks(123), 99)
        with (
            patch.object(custody.Path, "read_text", return_value="1 (public)"),
            patch.object(root, "_ticks") as ticks,
        ):
            self.assertIsNone(custody.gateway_peer_ticks(123))
            ticks.assert_not_called()
        with patch.object(custody.Path, "read_text", side_effect=FileNotFoundError):
            self.assertIsNone(custody.gateway_peer_ticks(123))

    def test_missing_socket_pidfd_never_creates_a_live_pin(self):
        conn = Mock()
        conn.getsockopt.side_effect = OSError("unsupported")
        with (
            patch.object(custody.sys, "platform", "linux"),
            patch.object(
                custody.os, "uname", return_value=SimpleNamespace(machine="x86_64")
            ),
        ):
            self.assertIsNone(custody.gateway_socket_pidfd(conn, 123))
        conn.getsockopt.assert_called_once()

    def test_broker_and_root_must_share_pid_namespace(self):
        with (
            patch.object(root.os, "stat") as stat_call,
            patch.object(
                root.Path, "read_text", return_value=f"{os.getpid()} (public)"
            ),
        ):
            stat_call.side_effect = [
                SimpleNamespace(st_dev=1, st_ino=2),
                SimpleNamespace(st_dev=1, st_ino=2),
            ]
            root.require_broker_pid_namespace(123)
            stat_call.side_effect = [
                SimpleNamespace(st_dev=1, st_ino=2),
                SimpleNamespace(st_dev=1, st_ino=3),
            ]
            with self.assertRaises(root.SupervisorRefused):
                root.require_broker_pid_namespace(123)
            with self.assertRaises(root.SupervisorRefused):
                root.require_broker_pid_namespace(True)
            with patch.object(root.Path, "read_text", return_value="1 (public)"):
                with self.assertRaises(root.SupervisorRefused):
                    root.require_broker_pid_namespace(123)

    def test_identity_checks_uid_capabilities_group_executable_and_liveness(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            peer = proc / "123"
            peer.mkdir(parents=True)
            executable = peer / "exe"
            executable.write_bytes(b"reviewed fixture executable")
            executable.chmod(0o444)
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            status = "Uid:\t2007 2007 2007 2007\nNoNewPrivs:\t1\n" + "".join(
                f"{name}:\t0000000000000000\n"
                for name in ("CapInh", "CapPrm", "CapEff", "CapAmb")
            )
            group = "/sfactoryharness" + "a" * 64 + ".slice"
            (peer / "status").write_text(status)
            (peer / "cgroup").write_text("0::" + group + "/gateway.service\n")
            grant = {"cgroup_path": "/sys/fs/cgroup" + group}
            real_fstat = os.fstat

            def root_fstat(fd):
                s = real_fstat(fd)
                return SimpleNamespace(
                    st_mode=s.st_mode,
                    st_uid=0,
                    st_size=s.st_size,
                    st_dev=s.st_dev,
                    st_ino=s.st_ino,
                    st_mtime_ns=s.st_mtime_ns,
                )

            with (
                patch.object(root, "Path", return_value=proc),
                patch.object(root, "_ticks", return_value=99),
                patch.object(root, "_owner_alive", return_value=True),
                patch.object(root.os, "fstat", side_effect=root_fstat),
            ):
                root.inspect_gateway_peer(grant, 123, 99, 2007, digest)
                with self.assertRaises(root.SupervisorRefused):
                    root.inspect_gateway_peer(grant, 123, 100, 2007, digest)
                for changed in (
                    status.replace("2007", "2001", 1),
                    status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
                    status.replace(
                        "CapEff:\t0000000000000000", "CapEff:\t0000000000000001"
                    ),
                ):
                    (peer / "status").write_text(changed)
                    with self.assertRaises(root.SupervisorRefused):
                        root.inspect_gateway_peer(grant, 123, 99, 2007, digest)
                (peer / "status").write_text(status)
                (peer / "cgroup").write_text("0::" + group + "-other/gateway.service\n")
                with self.assertRaises(root.SupervisorRefused):
                    root.inspect_gateway_peer(grant, 123, 99, 2007, digest)
                (peer / "cgroup").write_text("0::" + group + "/gateway.service\n")
                with self.assertRaises(root.SupervisorRefused):
                    root.inspect_gateway_peer(grant, 123, 99, 2007, "0" * 64)
                executable.chmod(0o666)
                with self.assertRaises(root.SupervisorRefused):
                    root.inspect_gateway_peer(grant, 123, 99, 2007, digest)

    def test_root_check_requires_v3_current_scope_guard_and_kernel_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {"attempt_id": "run_" + "a" * 64}
            (case / "grant.json").write_text(json.dumps(grant))
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {
                "schema": 3,
                "gateway_uid": 2007,
                "gateway_executable_sha256": "b" * 64,
            }
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.guard = threading.Lock()
            backend._case = Mock(return_value=case)
            backend.scope_preimage_v2 = Mock(return_value={})
            backend._current = Mock()
            backend._saved_scope = Mock(return_value="c" * 64)
            backend._kernel_scope = Mock()
            body = {
                "attempt": {"attempt_id": grant["attempt_id"]},
                "scope_sha256": "c" * 64,
                "pid": 123,
                "start_ticks": 99,
            }
            with (
                patch.object(
                    root, "protected", side_effect=lambda p, *_: p.read_bytes()
                ),
                patch.object(root, "check_guard") as guard,
                patch.object(root, "inspect_gateway_peer") as inspect,
                patch.object(root, "_ticks", return_value=44),
            ):
                guard.return_value = {"owner_pid": os.getpid(), "owner_ticks": 44}
                self.assertEqual(
                    backend.gateway_peer_v1(body),
                    {
                        "verified": True,
                        "pid": 123,
                        "start_ticks": 99,
                        "scope_sha256": "c" * 64,
                    },
                )
                inspect.assert_called_once_with(grant, 123, 99, 2007, "b" * 64)
                guard.assert_called_once_with(backend, grant)
                self.assertEqual(backend._current.call_count, 2)
                backend.cfg["schema"] = 2
                with self.assertRaises(root.SupervisorRefused):
                    backend.gateway_peer_v1(body)
                backend.cfg["schema"] = 3
                guard.return_value = {"owner_pid": os.getpid(), "owner_ticks": 45}
                with self.assertRaises(root.SupervisorRefused):
                    backend.gateway_peer_v1(body)
                self.assertEqual(inspect.call_count, 1)
                guard.side_effect = root.SupervisorRefused("guard lost")
                with self.assertRaises(root.SupervisorRefused):
                    backend.gateway_peer_v1(body)
                self.assertEqual(inspect.call_count, 1)
                with self.assertRaises(root.SupervisorRefused):
                    backend.gateway_peer_v1(body | {"pid": True})
