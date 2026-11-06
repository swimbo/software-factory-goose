
"""Root gateway process checks; synthetic proc files do not prove Linux custody."""

import contextlib
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import linux_supervisor as root
import gateway_custody as custody


class GatewayPeerTests(unittest.TestCase):
    def test_cold_ready_requires_exact_bounded_record_and_eof(self):
        cases = (
            (b'{"state":"cold-ready"}\n', True),
            (b'{"state":"cold-ready"}', False),
            (b'{"state":"cold-ready","state":"cold-ready"}\n', False),
            (b"{}\n{}\n", False),
            (b"{}\nextra", False),
            (b"x" * 4097, False),
            (b"", False),
        )
        for payload, accepted in cases:
            with self.subTest(payload=payload[:70]):
                reader, writer = os.pipe()
                try:
                    os.write(writer, payload)
                    os.close(writer)
                    writer = None
                    if accepted:
                        self.assertEqual(
                            root.read_gateway_cold_ready(
                                reader, int(time.time() * 1000) + 1000
                            ),
                            {"state": "cold-ready"},
                        )
                    else:
                        with self.assertRaises(root.SupervisorRefused):
                            root.read_gateway_cold_ready(
                                reader, int(time.time() * 1000) + 1000
                            )
                finally:
                    os.close(reader)
                    if writer is not None:
                        os.close(writer)

    def test_cold_ready_complete_record_without_eof_is_not_ready(self):
        reader, writer = os.pipe()
        try:
            os.write(writer, b"{}\n")
            started = time.monotonic()
            with self.assertRaisesRegex(
                root.SupervisorRefused, "root_gateway_cold_ready_timeout"
            ):
                root.read_gateway_cold_ready(reader, int(time.time() * 1000) + 40)
            self.assertLess(time.monotonic() - started, 1)
        finally:
            os.close(reader)
            os.close(writer)

    def test_cold_ready_rejects_each_changed_protected_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {"schema": 5, "gateway_uid": 2007}
            backend._current = Mock(return_value=case)
            child = SimpleNamespace(pid=456)
            grant = {
                "fixture": "public",
                "attempt_id": "run_" + "a" * 64,
                "broker_uid": 2005,
            }
            frozen = {
                "config_sha256": "a" * 64,
                "launch_sha256": "b" * 64,
                "grant_sha256": root.sha(grant),
                "scope_sha256": "c" * 64,
                "review_sha256": "d" * 64,
                "deadline_ms": int(time.time() * 1000) + 1000,
                "socket_device": 12,
                "socket_inode": 34,
            }
            prepared = {"deadline_ms": frozen["deadline_ms"], "child": {"ticks": 789}}
            receipt = {k: v for k, v in frozen.items() if k != "deadline_ms"}
            receipt.update(
                schema=1,
                state="cold-ready",
                pid=456,
                start_ticks=789,
                uid=2007,
                paid_ready=False,
            )
            substitutions = {
                "schema": True,
                "state": "paid-ready",
                "pid": 457,
                "start_ticks": 790,
                "uid": 2008,
                "paid_ready": 0,
                "socket_device": 13,
                "socket_inode": 35,
                **{
                    k: "f" * 64
                    for k in (
                        "config_sha256",
                        "launch_sha256",
                        "grant_sha256",
                        "scope_sha256",
                        "review_sha256",
                    )
                },
            }
            changed = [(k, receipt | {k: v}) for k, v in substitutions.items()]
            changed += [
                ("extra", receipt | {"unexpected": True}),
                ("missing", {k: v for k, v in receipt.items() if k != "paid_ready"}),
            ]
            for name, value in changed:
                with (
                    self.subTest(field=name),
                    patch.object(
                        root, "protected", return_value=json.dumps(prepared).encode()
                    ),
                    patch.object(root, "read_gateway_cold_ready", return_value=value),
                ):
                    with self.assertRaisesRegex(
                        root.SupervisorRefused, "^root_gateway_cold_ready_changed$"
                    ):
                        backend._accept_gateway_ready(grant, child, 99, frozen)
            self.assertFalse((case / "gateway-cold-ready.json").exists())
            backend.cfg["gateway_executable_sha256"] = "e" * 64
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.guard = threading.RLock()
            backend._saved_scope = Mock(return_value=frozen["scope_sha256"])
            backend._verify_gateway_launch = Mock()
            socket_info = SimpleNamespace(
                st_mode=stat.S_IFSOCK | 0o660,
                st_uid=2007,
                st_gid=2005,
                st_nlink=1,
                st_dev=12,
                st_ino=34,
            )

            def record(path, *args, **kwargs):
                if path.name == "gateway-parent-closed.json":
                    return json.dumps({"kernel_dev": 12, "kernel_ino": 34}).encode()
                return json.dumps(
                    prepared if path.name == "gateway-prepared.json" else frozen
                ).encode()

            with (
                patch.object(root, "protected", side_effect=record),
                patch.object(root, "read_gateway_cold_ready", return_value=receipt),
                patch.object(
                    root,
                    "gateway_bind_lock",
                    side_effect=lambda _: contextlib.nullcontext(),
                ),
                patch.object(root, "check_guard"),
                patch.object(root, "inspect_gateway_peer"),
                patch.object(root.os, "stat", return_value=socket_info),
                patch.object(root, "require_no_socket_copy"),
                patch.object(
                    backend, "_gateway_cleanup_custody", return_value={"fixture": True}
                ),
                patch.object(root, "store") as save,
            ):
                backend._accept_gateway_ready(grant, child, 99, frozen)
                self.assertEqual(save.call_count, 2)
                save.assert_any_call(case / "gateway-cold-ready.json", receipt)
                save.assert_any_call(
                    case / "gateway-cleanup-custody.json", {"fixture": True}
                )

    def test_root_freeze_preserves_reviewed_raw_template_hash_domains(self):
        # JSON RawMessage preserves lexical numbers, object order and escapes in
        # Go's typed policy digest. Outer Root metadata has a separate raw hash.
        policy = b'{"pricing_entries":[{"pricing":{"z":0.0000001,"a":1e+09,"null":null,"escaped":"\\u003c"}}]}'
        wire = b'{"later":1e-07,"earlier":null}'
        template_raw = (
            b'{"store_path":"/public.db","store":{},"review":{},"wire":'
            + wire
            + b',"wire_sha256":"'
            + b"f" * 64
            + b'","policy":'
            + policy
            + b',"policy_sha256":"'
            + b"e" * 64
            + b'","broker_path":"/broker","capture_path":"/capture"}'
        )
        now = int(time.time() * 1000)
        grant = {
            "attempt_id": "run_" + "a" * 64,
            "expires_at_ms": now + 60000,
            "broker_uid": 2005,
        }
        backend = object.__new__(root.RootSupervisor)
        backend.cfg = {
            "gateway_bootstrap_template": "/public-template.json",
            "gateway_bootstrap_template_sha256": hashlib.sha256(
                template_raw
            ).hexdigest(),
            "gateway_executable_sha256": "b" * 64,
            "gateway_uid": 2007,
            "capture_service_uid": 2008,
        }
        backend.catalog = Path("/public-catalog")
        backend._current = Mock(return_value=Path("/public-case"))
        backend._saved_scope = Mock(return_value="c" * 64)
        route = {
            "valid_from_ms": now - 1000,
            "valid_until_ms": now + 120000,
            "max_output_tokens": 16,
            "route_sha256": "d" * 64,
            "review_sha256": "e" * 64,
            "usage_tariff_sha256": "f" * 64,
        }
        backend._catalog = Mock(
            return_value=(
                {
                    "scope": {"route": route, "expires_at_ms": now + 120000},
                    "control_grant": {"expires_at_ms": now + 120000, "owner": "public"},
                },
                {"expires_at_ms": now + 120000},
            )
        )
        records = {
            "prepare-intent.json": b'{"attempt":{},"admission":{}}',
            "start-intent.json": b'{"public":true}',
            "public-template.json": template_raw,
            "gateway-bound.json": b'{"socket":{"path":"/public.sock","dev":12,"ino":34}}',
        }
        captured = bytearray()

        def write(fd, raw):
            captured.extend(raw)
            return len(raw)

        from contextlib import ExitStack

        with ExitStack() as stack:
            for name, value in {"MFD_CLOEXEC": 1, "MFD_ALLOW_SEALING": 2}.items():
                stack.enter_context(patch.object(root.os, name, value, create=True))
            for name, value in {
                "F_SEAL_SEAL": 1,
                "F_SEAL_SHRINK": 2,
                "F_SEAL_GROW": 4,
                "F_SEAL_WRITE": 8,
                "F_ADD_SEALS": 1033,
                "F_GET_SEALS": 1034,
            }.items():
                stack.enter_context(patch.object(root.fcntl, name, value, create=True))
            stack.enter_context(
                patch.object(
                    root,
                    "protected",
                    side_effect=lambda p, *a, **k: records.get(
                        Path(p).name, b'{"max_output_tokens":8}'
                    ),
                )
            )
            stack.enter_context(
                patch.object(root.os.path, "lexists", return_value=True)
            )
            stack.enter_context(
                patch.object(root, "factory_scope_digest", return_value="c" * 64)
            )
            stack.enter_context(patch.object(root, "_ticks", return_value=123))
            stack.enter_context(
                patch.object(
                    root.os, "fstat", return_value=SimpleNamespace(st_dev=56, st_ino=78)
                )
            )
            stack.enter_context(
                patch.object(root.os, "memfd_create", return_value=99, create=True)
            )
            stack.enter_context(patch.object(root.os, "write", side_effect=write))
            stack.enter_context(
                patch.object(
                    root.fcntl,
                    "fcntl",
                    side_effect=lambda fd, command, *a: 15 if command == 1034 else 0,
                )
            )
            stack.enter_context(patch.object(root, "store"))
            fd, frozen = backend._gateway_bootstrap(
                grant, SimpleNamespace(fileno=lambda: 98)
            )
        self.assertEqual(fd, 99)
        self.assertIn(b'"policy":' + policy, captured)
        self.assertIn(b'"wire":' + wire, captured)
        self.assertEqual(frozen["config_sha256"], hashlib.sha256(captured).hexdigest())
        decoded = json.loads(captured)
        self.assertEqual(decoded["grant_sha256"], root.sha(grant))
        self.assertEqual(decoded["scope_sha256"], "c" * 64)

    def test_socket_copy_scan_ignores_only_closed_descriptor_races(self):
        with patch.object(root.os, "listdir", return_value=["9"]):
            with patch.object(
                root.os, "fstat", side_effect=OSError(errno.EBADF, "closed")
            ):
                root.require_no_socket_copy((1, 2))
            with patch.object(
                root.os, "fstat", side_effect=OSError(errno.EACCES, "denied")
            ):
                with self.assertRaises(PermissionError):
                    root.require_no_socket_copy((1, 2))

    def test_schema_five_public_start_cannot_relaunch_consumed_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            consumed = b'{"public_consumed_start":true}'
            (case / "start-intent.json").write_bytes(consumed)
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {"schema": 5}
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.guard = threading.RLock()
            backend._current = Mock(return_value=case)
            backend._launch_gateway = Mock()
            backend._docker = Mock()
            with self.assertRaisesRegex(
                root.SupervisorRefused, "^root_start_already_attempted$"
            ):
                backend.start(
                    {
                        "grant": {"public": True},
                        "prompt": "public",
                        "declarations_sha256": "a" * 64,
                        "worker_protocol": "unix-json-v1",
                    }
                )
            backend._launch_gateway.assert_not_called()
            backend._docker.assert_not_called()
            self.assertEqual((case / "start-intent.json").read_bytes(), consumed)

    def test_schema_five_launch_fences_consumed_owner_loss_at_boundaries(self):
        for boundary in ("prepare", "release", "readiness"):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as directory,
            ):
                case = Path(directory)
                # Existing public start consumes this before any bind/launch.
                (case / "start-intent.json").write_text('{"public":true}')
                backend = object.__new__(root.RootSupervisor)
                backend.cfg = {"schema": 5}
                backend.gateway_children = {}
                grant = {"attempt_id": "run_" + "a" * 64}
                backend._saved = Mock(return_value=case)
                bound = Mock()
                child = Mock(pid=456)
                config_fd = os.open(os.devnull, os.O_RDONLY)
                gate_reader, gate_writer = os.pipe()
                backend._bind_gateway_socket = Mock(return_value=(bound, {}))
                backend._gateway_bootstrap = Mock(return_value=(config_fd, {}))
                backend._prepare_gateway = Mock(
                    return_value=(child, gate_writer, {"pid": 456})
                )
                backend._accept_gateway_ready = Mock()
                backend.revoke = Mock()
                if boundary == "prepare":
                    backend._gateway_bootstrap.side_effect = root.SupervisorRefused(
                        "root_owner_lost"
                    )

                def release(actual_grant, process, fd):
                    os.close(fd)
                    if boundary == "release":
                        raise root.SupervisorRefused("root_owner_lost")

                backend._release_gateway = Mock(side_effect=release)
                if boundary == "readiness":
                    backend._accept_gateway_ready.side_effect = root.SupervisorRefused(
                        "root_owner_lost"
                    )
                try:
                    with patch.object(
                        root,
                        "gateway_bind_lock",
                        side_effect=lambda _: contextlib.nullcontext(),
                    ):
                        with self.assertRaisesRegex(
                            root.SupervisorRefused, "^root_owner_lost$"
                        ):
                            backend._launch_gateway(grant, 99)
                    backend.revoke.assert_called_once_with({"grant": grant})
                    backend._bind_gateway_socket.assert_called_once()
                    self.assertTrue((case / "start-intent.json").exists())
                    self.assertFalse((case / "worker.json").exists())
                    if boundary == "prepare":
                        backend._prepare_gateway.assert_not_called()
                        backend._release_gateway.assert_not_called()
                        child.wait.assert_not_called()
                    else:
                        child.wait.assert_called_once_with(timeout=5)
                        self.assertIs(
                            backend.gateway_children[grant["attempt_id"]], child
                        )
                        self.assertEqual(os.read(gate_reader, 1), b"")
                    if boundary != "readiness":
                        backend._accept_gateway_ready.assert_not_called()
                finally:
                    os.close(gate_reader)
                    if boundary == "prepare":
                        os.close(config_fd)
                        os.close(gate_writer)

    def test_successful_cold_launch_reaps_exited_owned_child_without_observe(self):
        import subprocess
        import sys
        import time

        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {"schema": 5}
            backend.gateway_children = {}
            grant = {"attempt_id": "run_" + "a" * 64}
            backend._saved = Mock(return_value=case)
            bound = Mock()
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(120)"]
            )
            config = os.open(os.devnull, os.O_RDONLY)
            reader, writer = os.pipe()
            backend._bind_gateway_socket = Mock(return_value=(bound, {}))
            backend._gateway_bootstrap = Mock(return_value=(config, {}))
            backend._prepare_gateway = Mock(
                return_value=(child, writer, {"pid": child.pid})
            )
            backend._release_gateway = lambda grant, process, fd: os.close(fd)
            backend._accept_gateway_ready = Mock()
            try:
                with patch.object(
                    root,
                    "gateway_bind_lock",
                    side_effect=lambda _: contextlib.nullcontext(),
                ):
                    launched, _ = backend._launch_gateway(grant, 99)
                self.assertIs(launched, child)
                os.kill(child.pid, signal.SIGKILL)
                deadline = time.monotonic() + 2
                while child.returncode is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertIsNotNone(
                    child.returncode, "Root never joined its exited gateway"
                )
                with self.assertRaises(ChildProcessError):
                    os.waitpid(child.pid, os.WNOHANG)
                self.assertIs(backend.gateway_children[grant["attempt_id"]], child)
                self.assertFalse((case / "cleanup.json").exists())
            finally:
                child.kill()
                child.wait(timeout=5)
                os.close(reader)

    def test_root_launch_composes_bind_prepare_and_one_release(self):
        backend = object.__new__(root.RootSupervisor)
        backend.cfg = {"schema": 4}
        grant = {"public": "fixture"}
        bound = Mock()
        child = Mock()
        reader, writer = os.pipe()
        attached = {"pid": 456}
        backend._bind_gateway_socket = Mock(return_value=(bound, {"public": True}))
        backend._prepare_gateway = Mock(return_value=(child, writer, attached))

        def release(actual_grant, actual_child, fd):
            self.assertEqual((actual_grant, actual_child, fd), (grant, child, writer))
            os.close(fd)

        backend._release_gateway = Mock(side_effect=release)
        backend.revoke = Mock()
        try:
            self.assertEqual(backend._launch_gateway(grant, 99), (child, attached))
            backend._bind_gateway_socket.assert_called_once_with(grant)
            backend._prepare_gateway.assert_called_once_with(grant, bound, 99)
            backend._release_gateway.assert_called_once()
            backend.revoke.assert_not_called()
            child.wait.assert_not_called()
        finally:
            os.close(reader)

    def test_root_launch_revokes_and_joins_after_unknown_release(self):
        backend = object.__new__(root.RootSupervisor)
        backend.cfg = {"schema": 4}
        grant = {"public": "fixture"}
        bound = Mock()
        child = Mock()
        reader, writer = os.pipe()
        backend._bind_gateway_socket = Mock(return_value=(bound, {}))
        backend._prepare_gateway = Mock(return_value=(child, writer, {"pid": 456}))

        def release(_, __, fd):
            os.close(fd)
            raise OSError("public release failure")

        backend._release_gateway = Mock(side_effect=release)
        backend.revoke = Mock()
        try:
            with self.assertRaisesRegex(OSError, "public release failure"):
                backend._launch_gateway(grant, 99)
            backend.revoke.assert_called_once_with({"grant": grant})
            child.wait.assert_called_once_with(timeout=5)
            self.assertEqual(os.read(reader, 1), b"")
        finally:
            os.close(reader)

    def test_root_launch_reports_unknown_cleanup_without_rearming(self):
        backend = object.__new__(root.RootSupervisor)
        backend.cfg = {"schema": 4}
        grant = {"public": "fixture"}
        bound = Mock()
        backend._bind_gateway_socket = Mock(return_value=(bound, {}))
        backend._prepare_gateway = Mock(side_effect=OSError("public failure"))
        backend._release_gateway = Mock()
        backend.revoke = Mock(side_effect=OSError("public cleanup failure"))
        with self.assertRaisesRegex(
            root.SupervisorRefused, "root_gateway_launch_cleanup_unknown"
        ):
            backend._launch_gateway(grant, 99)
        bound.close.assert_called_once()
        backend.revoke.assert_called_once_with({"grant": grant})
        backend._release_gateway.assert_not_called()

    def test_root_launch_does_not_claim_cleanup_when_child_will_not_join(self):
        backend = object.__new__(root.RootSupervisor)
        backend.cfg = {"schema": 4}
        grant = {"public": "fixture"}
        bound = Mock()
        child = Mock()
        child.wait.side_effect = subprocess.TimeoutExpired("public-child", 5)
        reader, writer = os.pipe()
        backend._bind_gateway_socket = Mock(return_value=(bound, {}))
        backend._prepare_gateway = Mock(return_value=(child, writer, {"pid": 456}))

        def release(_, __, fd):
            os.close(fd)
            raise OSError("public release failure")

        backend._release_gateway = Mock(side_effect=release)
        backend.revoke = Mock()
        try:
            with self.assertRaisesRegex(
                root.SupervisorRefused, "root_gateway_launch_join_unknown"
            ):
                backend._launch_gateway(grant, 99)
            backend.revoke.assert_called_once_with({"grant": grant})
            child.wait.assert_called_once_with(timeout=5)
            self.assertEqual(os.read(reader, 1), b"")
        finally:
            os.close(reader)

    def release_fixture(self, case, gate):
        grant = {
            "attempt_id": "run_" + "a" * 64,
            "broker_uid": 2005,
            "cgroup_path": "/sys/fs/cgroup/public.slice",
            "cgroup_dev": 1,
            "cgroup_ino": 2,
            "expires_at_ms": time.time_ns() // 1000000 + 12000,
        }
        backend = object.__new__(root.RootSupervisor)
        backend.cfg = {"schema": 4, "gateway_uid": 2007}
        backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
        backend.guard = threading.Lock()
        backend._saved = Mock(return_value=case)
        backend._current = Mock(return_value=case)
        backend._saved_scope = Mock(return_value="c" * 64)
        backend._kernel_scope = Mock()
        child = {
            "path": grant["cgroup_path"] + "/gateway",
            "dev": 3,
            "ino": 4,
            "pid": 456,
            "ticks": 789,
        }
        intent = {
            "grant_sha256": root.sha(grant),
            "scope_sha256": "c" * 64,
            "gateway_uid": 2007,
        }
        info = os.fstat(gate)
        namespace = {
            "grant_sha256": root.sha(grant),
            "scope_sha256": "c" * 64,
            "pid": child["pid"],
            "ticks": child["ticks"],
            "namespace": {"dev": 11, "ino": 12},
        }
        prepared = {
            "grant_sha256": root.sha(grant),
            "child": child,
            "gate_dev": info.st_dev,
            "gate_ino": info.st_ino,
            "deadline_ms": grant["expires_at_ms"],
            "namespace": namespace,
        }
        (case / "gateway-userns.json").write_text(json.dumps(namespace))
        (case / "gateway-prepared.json").write_text(json.dumps(prepared))
        (case / "gateway-attached.json").write_text(
            json.dumps({"intent": intent, "child": child})
        )
        return backend, grant, SimpleNamespace(pid=456), prepared

    def test_root_release_is_one_use_and_binds_gate_and_child(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            reader, writer = os.pipe()
            duplicate = os.dup(writer)
            backend, grant, process, prepared = self.release_fixture(case, writer)
            guard = {"owner_pid": os.getpid(), "owner_ticks": 123}
            try:
                with (
                    patch.object(
                        root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                    ),
                    patch.object(
                        root, "protected", side_effect=lambda p, *_: p.read_bytes()
                    ),
                    patch.object(root, "check_guard", return_value=guard) as check,
                    patch.object(root, "_ticks", return_value=123),
                    patch.object(root, "inspect_prepared_gateway") as inspect,
                    patch.object(
                        root, "inspect_gateway_user_namespace"
                    ) as userns_inspect,
                ):
                    result = backend._release_gateway(grant, process, writer)
                    self.assertEqual(os.read(reader, 1), b"G")
                    self.assertEqual(
                        result,
                        {
                            "grant_sha256": root.sha(grant),
                            "prepared_sha256": root.sha(prepared),
                        },
                    )
                    self.assertEqual(check.call_count, 2)
                    self.assertEqual(inspect.call_count, 2)
                    self.assertEqual(userns_inspect.call_count, 2)
                    self.assertEqual(
                        json.loads((case / "gateway-released.json").read_text()), result
                    )
                    with self.assertRaises(FileExistsError):
                        backend._release_gateway(grant, process, duplicate)
                    self.assertEqual(os.read(reader, 1), b"")
            finally:
                os.close(reader)

    def test_root_release_refuses_changed_gate_and_guard_loss_after_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            reader, writer = os.pipe()
            other_reader, other_writer = os.pipe()
            backend, grant, process, _ = self.release_fixture(case, writer)
            guard = {"owner_pid": os.getpid(), "owner_ticks": 123}
            try:
                with (
                    patch.object(
                        root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                    ),
                    patch.object(
                        root, "protected", side_effect=lambda p, *_: p.read_bytes()
                    ),
                    patch.object(root, "check_guard", return_value=guard) as check,
                    patch.object(root, "_ticks", return_value=123),
                    patch.object(root, "inspect_prepared_gateway") as inspect,
                    patch.object(root, "inspect_gateway_user_namespace"),
                ):
                    with self.assertRaisesRegex(
                        root.SupervisorRefused, "root_gateway_gate_changed"
                    ):
                        backend._release_gateway(grant, process, other_writer)
                    self.assertFalse((case / "gateway-release-intent.json").exists())
                    inspect.assert_not_called()
                    check.side_effect = [guard, root.SupervisorRefused("guard lost")]
                    with self.assertRaisesRegex(root.SupervisorRefused, "guard lost"):
                        backend._release_gateway(grant, process, writer)
                    self.assertTrue((case / "gateway-release-intent.json").exists())
                    self.assertFalse((case / "gateway-released.json").exists())
                    self.assertEqual(os.read(reader, 1), b"")
            finally:
                os.close(reader)
                os.close(other_reader)

    def test_root_release_accepts_unsigned_64_bit_pipe_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            reader, writer = os.pipe()
            backend, grant, process, prepared = self.release_fixture(case, writer)
            prepared["gate_ino"] = 2**63 + 123
            (case / "gateway-prepared.json").write_text(json.dumps(prepared))
            original_fstat = os.fstat

            def gate_info(fd):
                info = original_fstat(fd)
                if fd != writer:
                    return info
                return SimpleNamespace(
                    st_mode=info.st_mode,
                    st_dev=info.st_dev,
                    st_ino=prepared["gate_ino"],
                )

            try:
                with (
                    patch.object(
                        root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                    ),
                    patch.object(
                        root, "protected", side_effect=lambda p, *_: p.read_bytes()
                    ),
                    patch.object(
                        root,
                        "check_guard",
                        return_value={"owner_pid": os.getpid(), "owner_ticks": 123},
                    ),
                    patch.object(root, "_ticks", return_value=123),
                    patch.object(root, "inspect_prepared_gateway"),
                    patch.object(root, "inspect_gateway_user_namespace"),
                    patch.object(root.os, "fstat", side_effect=gate_info),
                ):
                    backend._release_gateway(grant, process, writer)
                    self.assertEqual(os.read(reader, 1), b"G")
            finally:
                os.close(reader)

    def test_root_release_refuses_substituted_namespace_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            reader, writer = os.pipe()
            backend, grant, process, prepared = self.release_fixture(case, writer)
            altered = dict(prepared["namespace"])
            altered["namespace"] = {"dev": 11, "ino": 13}
            (case / "gateway-userns.json").write_text(json.dumps(altered))
            try:
                with (
                    patch.object(
                        root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                    ),
                    patch.object(
                        root, "protected", side_effect=lambda p, *_: p.read_bytes()
                    ),
                    patch.object(
                        root,
                        "check_guard",
                        return_value={"owner_pid": os.getpid(), "owner_ticks": 123},
                    ),
                    patch.object(root, "_ticks", return_value=123),
                    patch.object(root, "inspect_gateway_user_namespace") as inspect,
                ):
                    with self.assertRaisesRegex(
                        root.SupervisorRefused, "root_gateway_prepared_receipt_changed"
                    ):
                        backend._release_gateway(grant, process, writer)
                    inspect.assert_not_called()
                    self.assertFalse((case / "gateway-release-intent.json").exists())
                    self.assertEqual(os.read(reader, 1), b"")
            finally:
                os.close(reader)

    def test_root_release_rechecks_gate_after_final_child_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            reader, writer = os.pipe()
            other_reader, other_writer = os.pipe()
            backend, grant, process, _ = self.release_fixture(case, writer)
            checks = 0

            def replace_after_check(*_):
                nonlocal checks
                checks += 1
                if checks == 2:
                    os.dup2(other_writer, writer, inheritable=False)

            try:
                with (
                    patch.object(
                        root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                    ),
                    patch.object(
                        root, "protected", side_effect=lambda p, *_: p.read_bytes()
                    ),
                    patch.object(
                        root,
                        "check_guard",
                        return_value={"owner_pid": os.getpid(), "owner_ticks": 123},
                    ),
                    patch.object(root, "_ticks", return_value=123),
                    patch.object(
                        root,
                        "inspect_prepared_gateway",
                        side_effect=replace_after_check,
                    ),
                    patch.object(root, "inspect_gateway_user_namespace"),
                ):
                    with self.assertRaisesRegex(
                        root.SupervisorRefused, "root_gateway_gate_changed"
                    ):
                        backend._release_gateway(grant, process, writer)
                self.assertTrue((case / "gateway-release-intent.json").exists())
                self.assertFalse((case / "gateway-released.json").exists())
                self.assertEqual(os.read(reader, 1), b"")
                os.close(other_writer)
                other_writer = None
                self.assertEqual(os.read(other_reader, 1), b"")
            finally:
                os.close(reader)
                os.close(other_reader)
                if other_writer is not None:
                    os.close(other_writer)

    def test_root_prepare_spawns_gated_child_and_never_releases_it(self):
        self.prepare_child_scenario()

    def test_root_prepare_joins_schema_five_child_on_attachment_owner_loss(self):
        self.prepare_child_scenario(fail_attach=True)

    def prepare_child_scenario(self, *, fail_attach=False):
        with (
            tempfile.TemporaryDirectory() as directory,
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bound,
        ):
            case = Path(directory)
            grant = {
                "attempt_id": "run_" + "a" * 64,
                "broker_uid": 2005,
                "cgroup_path": "/sys/fs/cgroup/public.slice",
                "cgroup_dev": 1,
                "cgroup_ino": 2,
                "boot_id": "a" * 36,
                "expires_at_ms": time.time_ns() // 1000000 + 12000,
            }
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {
                "schema": 5,
                "capture_service_uid": 2008,
                "gateway_uid": 2007,
                "gateway_executable_sha256": "b" * 64,
                "python": sys.executable,
            }
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.guard = threading.Lock()
            backend._saved = Mock(return_value=case)
            backend._current = Mock(return_value=case)
            backend._saved_scope = Mock(return_value="c" * 64)
            backend._kernel_scope = Mock()
            attached = {
                "path": grant["cgroup_path"] + "/gateway",
                "dev": 3,
                "ino": 4,
                "pid": 456,
                "ticks": 123,
            }
            backend._attach_gateway = Mock(return_value=attached)
            intent = {
                "grant_sha256": root.sha(grant),
                "scope_sha256": "c" * 64,
                "gateway_uid": 2007,
                "broker_gid": 2005,
            }
            record = {
                "intent": intent,
                "socket": {
                    "path": "/var/lib/sfactory-harness/gw/" + "a" * 64 + ".sock",
                    "dev": 5,
                    "ino": 6,
                },
            }
            (case / "gateway-bound.json").write_text(json.dumps(record))
            if fail_attach:
                backend._attach_gateway.side_effect = root.SupervisorRefused(
                    "root_owner_lost"
                )
            child = Mock(pid=456)
            child.poll.return_value = None
            original_socket = bound.fileno()
            program = os.open(os.devnull, os.O_RDONLY)
            helper = os.open(os.devnull, os.O_RDONLY)
            bootstrap = os.open(os.devnull, os.O_RDONLY)
            config_fd = os.open(os.devnull, os.O_RDONLY)
            cold_reader, cold_writer = os.pipe()
            held_map = []

            def spawn(argv, **kwargs):
                self.assertTrue((case / "gateway-spawn-intent.json").exists())
                self.assertNotIn("user", kwargs)
                self.assertEqual(kwargs["env"], {})
                self.assertIn(original_socket, kwargs["pass_fds"])
                config = json.loads(argv[-1])
                self.assertEqual(config["capture_uid"], 2008)
                self.assertEqual(config["helper_config"]["bootstrap_fd"], config_fd)
                self.assertEqual(config["helper_config"]["cold_ready_fd"], cold_writer)
                self.assertIn(config_fd, kwargs["pass_fds"])
                self.assertIn(cold_writer, kwargs["pass_fds"])
                held_map.append(os.dup(config["map_fd"]))
                os.write(config["ready_fd"], b"N")
                os.write(config["helper_config"]["ready_fd"], b"R")
                return child

            try:
                with (
                    patch.object(
                        root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                    ),
                    patch.object(
                        root, "protected", side_effect=lambda p, *_: p.read_bytes()
                    ),
                    patch.object(
                        root,
                        "check_guard",
                        return_value={"owner_pid": os.getpid(), "owner_ticks": 123},
                    ),
                    patch.object(root, "_ticks", return_value=123),
                    patch.object(root, "stage_gateway_exec", return_value=helper),
                    patch.object(root, "stage_gateway_userns", return_value=bootstrap),
                    patch.object(
                        root,
                        "map_gateway_user_namespace",
                        return_value={"dev": 11, "ino": 12},
                    ),
                    patch.object(root, "inspect_gateway_user_namespace"),
                    patch.object(root, "require_no_socket_copy"),
                    patch.object(root.subprocess, "Popen", side_effect=spawn),
                ):
                    if fail_attach:
                        with self.assertRaisesRegex(
                            root.SupervisorRefused, "^root_owner_lost$"
                        ):
                            backend._prepare_gateway(
                                grant,
                                bound,
                                program,
                                bootstrap_config_fd=config_fd,
                                cold_ready_fd=cold_writer,
                            )
                        child.kill.assert_called_once()
                        child.wait.assert_called_once_with(timeout=5)
                        self.assertTrue((case / "gateway-spawn-intent.json").exists())
                        self.assertFalse((case / "gateway-prepared.json").exists())
                        self.assertFalse(
                            (case / "gateway-release-intent.json").exists()
                        )
                        return
                    actual, gate, receipt = backend._prepare_gateway(
                        grant,
                        bound,
                        program,
                        bootstrap_config_fd=config_fd,
                        cold_ready_fd=cold_writer,
                    )
                try:
                    self.assertEqual((actual, receipt), (child, attached))
                    self.assertEqual(bound.fileno(), -1)
                    self.assertFalse(os.get_inheritable(gate))
                    self.assertTrue((case / "gateway-prepared.json").exists())
                    self.assertTrue((case / "gateway-userns.json").exists())
                    self.assertEqual(os.read(held_map[0], 1), b"M")
                    backend._attach_gateway.assert_called_once_with(grant, child)
                    child.kill.assert_not_called()
                finally:
                    os.close(gate)
            finally:
                for fd in held_map:
                    os.close(fd)
                os.close(program)
                os.close(config_fd)
                os.close(cold_reader)
                os.close(cold_writer)

    def test_root_prepare_kills_child_when_barrier_fails_before_ready(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bound,
        ):
            case = Path(directory)
            grant = {
                "attempt_id": "run_" + "a" * 64,
                "broker_uid": 2005,
                "cgroup_path": "/sys/fs/cgroup/public.slice",
                "cgroup_dev": 1,
                "cgroup_ino": 2,
                "boot_id": "a" * 36,
                "expires_at_ms": time.time_ns() // 1000000 + 12000,
            }
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {
                "schema": 4,
                "gateway_uid": 2007,
                "gateway_executable_sha256": "b" * 64,
                "python": sys.executable,
            }
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.guard = threading.Lock()
            backend._saved = Mock(return_value=case)
            backend._current = Mock(return_value=case)
            backend._saved_scope = Mock(return_value="c" * 64)
            backend._kernel_scope = Mock()
            backend._attach_gateway = Mock()
            intent = {
                "grant_sha256": root.sha(grant),
                "scope_sha256": "c" * 64,
                "gateway_uid": 2007,
                "broker_gid": 2005,
            }
            (case / "gateway-bound.json").write_text(
                json.dumps(
                    {
                        "intent": intent,
                        "socket": {
                            "path": "/var/lib/sfactory-harness/gw/"
                            + "a" * 64
                            + ".sock",
                            "dev": 5,
                            "ino": 6,
                        },
                    }
                )
            )
            child = Mock(pid=456)
            child.poll.return_value = None
            program = os.open(os.devnull, os.O_RDONLY)
            helper = os.open(os.devnull, os.O_RDONLY)
            bootstrap = os.open(os.devnull, os.O_RDONLY)
            try:
                with (
                    patch.object(
                        root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                    ),
                    patch.object(
                        root, "protected", side_effect=lambda p, *_: p.read_bytes()
                    ),
                    patch.object(
                        root,
                        "check_guard",
                        return_value={"owner_pid": os.getpid(), "owner_ticks": 123},
                    ),
                    patch.object(root, "_ticks", return_value=123),
                    patch.object(root, "stage_gateway_exec", return_value=helper),
                    patch.object(root, "stage_gateway_userns", return_value=bootstrap),
                    patch.object(root, "require_no_socket_copy"),
                    patch.object(root.subprocess, "Popen", return_value=child),
                ):
                    with self.assertRaisesRegex(
                        root.SupervisorRefused, "root_gateway_namespace_not_ready"
                    ):
                        backend._prepare_gateway(grant, bound, program)
                child.kill.assert_called_once()
                child.wait.assert_called_once_with(timeout=5)
                backend._attach_gateway.assert_not_called()
                self.assertEqual(bound.fileno(), -1)
                self.assertTrue((case / "gateway-spawn-intent.json").exists())
                self.assertFalse((case / "gateway-prepared.json").exists())
            finally:
                os.close(program)

    def test_gateway_exec_pin_matches_reviewed_source_and_refuses_changed_bytes(self):
        helper = Path(root.__file__).with_name("linux_gateway_exec.py")
        self.assertEqual(
            hashlib.sha256(helper.read_bytes()).hexdigest(), root.GATEWAY_EXEC_SHA256
        )
        with patch.object(root, "protected", return_value=b"changed source"):
            with self.assertRaisesRegex(
                root.SupervisorRefused, "root_gateway_exec_changed"
            ):
                root.stage_gateway_exec()

    def test_gateway_userns_pin_matches_reviewed_source_and_refuses_changed_bytes(self):
        helper = Path(root.__file__).with_name("linux_gateway_userns_bootstrap.py")
        self.assertEqual(
            hashlib.sha256(helper.read_bytes()).hexdigest(), root.GATEWAY_USERNS_SHA256
        )
        with patch.object(root, "protected", return_value=b"changed source"):
            with self.assertRaisesRegex(
                root.SupervisorRefused, "root_gateway_exec_changed"
            ):
                root.stage_gateway_userns()

    @unittest.skipUnless(sys.platform == "linux", "Linux memfd required")
    def test_gateway_exec_stage_is_sealed_and_close_on_exec(self):
        helper = Path(root.__file__).with_name("linux_gateway_exec.py")
        source = helper.read_bytes()
        with patch.object(root, "protected", return_value=source) as protected:
            fd = root.stage_gateway_exec()
        try:
            self.assertEqual(os.read(fd, len(source) + 1), source)
            self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(
                protected.call_args.kwargs["expected"], root.GATEWAY_EXEC_SHA256
            )
            with self.assertRaises(PermissionError):
                os.write(fd, b"changed")
            with self.assertRaises(PermissionError):
                os.ftruncate(fd, 0)
            with self.assertRaises(PermissionError):
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 0)
            child = subprocess.run(
                [sys.executable, "-I", "-B", f"/proc/self/fd/{fd}", "{}"],
                pass_fds=(fd,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )
            self.assertNotEqual(child.returncode, 0)
            self.assertEqual(child.stderr.strip(), b"gateway_exec_refused")
        finally:
            os.close(fd)

    def test_remove_unhanded_socket_checks_inode_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "socket"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.bind(str(path))
                info = path.lstat()
                identity = {"path": str(path), "dev": info.st_dev, "ino": info.st_ino}
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with patch.object(
                        root,
                        "gateway_socket_parent",
                        return_value=contextlib.nullcontext((fd, path.name, str(path))),
                    ):
                        with self.assertRaises(root.SupervisorRefused):
                            root.remove_gateway_socket(
                                "run_" + "a" * 64, identity | {"ino": info.st_ino + 1}
                            )
                        self.assertTrue(path.exists())
                        root.remove_gateway_socket("run_" + "a" * 64, identity)
                        self.assertFalse(path.exists())
                        root.remove_gateway_socket("run_" + "a" * 64, identity)
                        path.write_text("public fixture")
                        other = path.lstat()
                        with self.assertRaises(root.SupervisorRefused):
                            root.remove_gateway_socket(
                                "run_" + "a" * 64,
                                {
                                    "path": str(path),
                                    "dev": other.st_dev,
                                    "ino": other.st_ino,
                                },
                            )
                        self.assertEqual(path.read_text(), "public fixture")
                finally:
                    os.close(fd)

    def test_gateway_absence_check_refuses_invalid_or_unreadable_path(self):
        with patch.object(
            root.os, "open", side_effect=PermissionError("fixture denied")
        ) as open_path:
            with self.assertRaises(root.SupervisorRefused):
                root.gateway_socket_absent("run_bad")
            open_path.assert_not_called()
            with self.assertRaises(PermissionError):
                root.gateway_socket_absent("run_" + "a" * 64)

    def test_supervisor_import_does_not_require_socket_helper_for_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "harness"
            shutil.copytree(
                Path(__file__).parent,
                source,
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            (source / "linux_gateway_socket.py").unlink()
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    "import sys;sys.path.insert(0,sys.argv[1]);import linux_supervisor",
                    str(source),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(
                result.returncode, 0, result.stderr.decode(errors="replace")
            )

    def test_gateway_socket_loader_requires_digest_and_verified_source(self):
        source = b"def bind_gateway_socket(*args):\n    return args\n"
        helper = Path(root.__file__).with_name("linux_gateway_socket.py")
        self.assertEqual(
            hashlib.sha256(helper.read_bytes()).hexdigest(), root.GATEWAY_SOCKET_SHA256
        )
        with patch.object(root, "protected", return_value=source) as verified:
            for invalid in ("invalid", "a" * 64):
                with self.assertRaises(root.SupervisorRefused):
                    root.load_gateway_socket(invalid)
            verified.assert_not_called()
            binder = root.load_gateway_socket(root.GATEWAY_SOCKET_SHA256)
            self.assertEqual(binder(1, 2, 3), (1, 2, 3))
            self.assertEqual(
                verified.call_args.kwargs["expected"], root.GATEWAY_SOCKET_SHA256
            )
            self.assertEqual(verified.call_args.args[1], 0o444)

    def test_gateway_bind_lock_refuses_a_competing_holder(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            original = os.fstat

            def root_owned(fd):
                info = original(fd)
                return SimpleNamespace(
                    st_mode=info.st_mode,
                    st_uid=0,
                    st_nlink=info.st_nlink,
                    st_dev=info.st_dev,
                    st_ino=info.st_ino,
                )

            with (
                patch.object(root.os, "fstat", side_effect=root_owned),
                patch.object(root, "_no_acl"),
            ):
                with root.gateway_bind_lock(case):
                    with self.assertRaisesRegex(
                        root.SupervisorRefused, "root_gateway_bind_busy"
                    ):
                        with root.gateway_bind_lock(case):
                            self.fail("concurrent lock acquired")
                with root.gateway_bind_lock(case):
                    pass

    def test_current_grant_refuses_fenced_or_cleaned_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            (case / "prepare-intent.json").write_text('{"attempt":{},"admission":{}}')
            backend = object.__new__(root.RootSupervisor)
            backend._saved = Mock(return_value=case)
            backend._catalog = Mock()
            grant = {"expires_at_ms": time.time_ns() // 1000000 + 10000}
            with patch.object(
                root, "protected", side_effect=lambda p, *_: p.read_bytes()
            ):
                self.assertEqual(backend._current(grant), case)
                for marker in ("execution-fenced.json", "cleanup.json"):
                    path = case / marker
                    path.write_text("{}")
                    with self.assertRaises(root.SupervisorRefused):
                        backend._current(grant)
                    path.unlink()

    def test_root_attaches_only_after_bound_socket_and_persists_leaf_before_move(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {
                "attempt_id": "run_" + "a" * 64,
                "broker_uid": 2005,
                "cgroup_path": "/sys/fs/cgroup/public.slice",
            }
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {"schema": 4, "gateway_uid": 2007}
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.guard = threading.Lock()
            backend._saved = Mock(return_value=case)
            backend._current = Mock(return_value=case)
            backend._saved_scope = Mock(return_value="c" * 64)
            backend._kernel_scope = Mock()
            guard = {"owner_pid": os.getpid(), "owner_ticks": 123}
            intent = {
                "grant_sha256": root.sha(grant),
                "scope_sha256": "c" * 64,
                "gateway_uid": 2007,
                "broker_gid": 2005,
            }
            socket_identity = {
                "path": "/var/lib/sfactory-harness/gw/" + "a" * 64 + ".sock",
                "dev": 1,
                "ino": 2,
            }
            bound = {"intent": intent, "socket": socket_identity}
            leaf = {"path": grant["cgroup_path"] + "/gateway", "dev": 3, "ino": 4}
            child = SimpleNamespace(pid=456)
            attached = leaf | {"pid": child.pid, "ticks": 789}

            def move(actual_grant, actual_process, uid, *, on_created):
                self.assertEqual(
                    (actual_grant, actual_process, uid), (grant, child, 2007)
                )
                self.assertTrue((case / "gateway-leaf-intent.json").exists())
                on_created(leaf)
                self.assertEqual(
                    json.loads((case / "gateway-leaf-created.json").read_text())[
                        "leaf"
                    ],
                    leaf,
                )
                return attached

            with (
                patch.object(
                    root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                ),
                patch.object(
                    root, "protected", side_effect=lambda p, *_: p.read_bytes()
                ),
                patch.object(root, "check_guard", return_value=guard) as check,
                patch.object(root, "_ticks", return_value=123),
                patch.object(root, "attach_gateway_child", side_effect=move) as attach,
            ):
                for name in ("gateway-created.json", "gateway-bound.json"):
                    (case / name).write_text(json.dumps(bound))
                (case / "gateway-parent-closed.json").write_text(
                    json.dumps(
                        {
                            "intent": intent,
                            "socket": socket_identity,
                            "child_pid": child.pid,
                            "child_ticks": 789,
                            "kernel_dev": 1,
                            "kernel_ino": 2,
                        }
                    )
                )
                self.assertEqual(backend._attach_gateway(grant, child), attached)
                self.assertEqual(check.call_count, 2)
                self.assertEqual(
                    json.loads((case / "gateway-attached.json").read_text())["child"],
                    attached,
                )
                with self.assertRaises(FileExistsError):
                    backend._attach_gateway(grant, child)
                attach.assert_called_once()

    def test_root_attach_refuses_changed_bound_socket_and_lost_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {
                "attempt_id": "run_" + "a" * 64,
                "broker_uid": 2005,
                "cgroup_path": "/sys/fs/cgroup/public.slice",
            }
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {"schema": 4, "gateway_uid": 2007}
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.guard = threading.Lock()
            backend._saved = Mock(return_value=case)
            backend._current = Mock(return_value=case)
            backend._saved_scope = Mock(return_value="c" * 64)
            backend._kernel_scope = Mock()
            with (
                patch.object(
                    root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                ),
                patch.object(
                    root, "protected", side_effect=lambda p, *_: p.read_bytes()
                ),
                patch.object(
                    root,
                    "check_guard",
                    return_value={"owner_pid": os.getpid(), "owner_ticks": 123},
                ) as check,
                patch.object(root, "_ticks", return_value=123),
                patch.object(root, "attach_gateway_child") as attach,
            ):
                (case / "gateway-created.json").write_text("{}")
                (case / "gateway-bound.json").write_text("{}")
                (case / "gateway-parent-closed.json").write_text("{}")
                with self.assertRaisesRegex(
                    root.SupervisorRefused, "root_gateway_bound_receipt_changed"
                ):
                    backend._attach_gateway(grant, SimpleNamespace(pid=456))
                self.assertFalse((case / "gateway-leaf-intent.json").exists())
                check.side_effect = root.SupervisorRefused("guard lost")
                with self.assertRaisesRegex(root.SupervisorRefused, "guard lost"):
                    backend._attach_gateway(grant, SimpleNamespace(pid=456))
                attach.assert_not_called()
                intent = {
                    "grant_sha256": root.sha(grant),
                    "scope_sha256": "c" * 64,
                    "gateway_uid": 2007,
                    "broker_gid": 2005,
                }
                bound = {
                    "intent": intent,
                    "socket": {
                        "path": "/var/lib/sfactory-harness/gw/" + "a" * 64 + ".sock",
                        "dev": 1,
                        "ino": 2,
                    },
                }
                for name in ("gateway-created.json", "gateway-bound.json"):
                    (case / name).write_text(json.dumps(bound))
                (case / "gateway-parent-closed.json").write_text(
                    json.dumps(
                        {
                            "intent": intent,
                            "socket": bound["socket"],
                            "child_pid": 456,
                            "child_ticks": 789,
                            "kernel_dev": 1,
                            "kernel_ino": 2,
                        }
                    )
                )
                leaf = {"path": grant["cgroup_path"] + "/gateway", "dev": 3, "ino": 4}

                def move(*args, on_created):
                    on_created(leaf)
                    return leaf | {"pid": 456, "ticks": 789}

                attach.side_effect = move
                check.side_effect = [
                    {"owner_pid": os.getpid(), "owner_ticks": 123},
                    root.SupervisorRefused("guard lost after move"),
                ]
                with self.assertRaisesRegex(
                    root.SupervisorRefused, "guard lost after move"
                ):
                    backend._attach_gateway(grant, SimpleNamespace(pid=456))
                self.assertTrue((case / "gateway-leaf-created.json").exists())
                self.assertFalse((case / "gateway-attached.json").exists())

    def test_root_bound_socket_requires_current_guard_and_one_use_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {"attempt_id": "run_" + "a" * 64, "broker_uid": 2005}
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {
                "schema": 4,
                "gateway_uid": 2007,
                "gateway_socket_sha256": "d" * 64,
            }
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.guard = threading.Lock()
            backend._saved = Mock(return_value=case)
            backend._current = Mock(return_value=case)
            backend._saved_scope = Mock(return_value="c" * 64)
            backend._kernel_scope = Mock()
            sock = Mock()
            identity = {
                "path": "/var/lib/sfactory-harness/gw/" + "a" * 64 + ".sock",
                "dev": 1,
                "ino": 2,
            }
            bind = Mock(
                side_effect=lambda *_, on_created: (
                    on_created(identity),
                    (sock, identity),
                )[1]
            )
            ready = {"owner_pid": os.getpid(), "owner_ticks": 44}
            with (
                patch.object(root, "load_gateway_socket", return_value=bind),
                patch.object(root, "check_guard", return_value=ready) as guard,
                patch.object(root, "_ticks", return_value=44),
                patch.object(
                    root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                ),
            ):
                backend.cfg["schema"] = 3
                with self.assertRaises(root.SupervisorRefused):
                    backend._bind_gateway_socket(grant)
                bind.assert_not_called()
                backend.cfg["schema"] = 4
                guard.return_value = {"owner_pid": os.getpid(), "owner_ticks": 45}
                with self.assertRaises(root.SupervisorRefused):
                    backend._bind_gateway_socket(grant)
                bind.assert_not_called()
                self.assertFalse((case / "gateway-bind-intent.json").exists())
                guard.return_value = ready
                actual, receipt = backend._bind_gateway_socket(grant)
                self.assertIs(actual, sock)
                self.assertEqual(receipt["socket"], identity)
                self.assertEqual(bind.call_args.args, ("a" * 64, 2007, 2005))
                self.assertTrue(callable(bind.call_args.kwargs["on_created"]))
                self.assertEqual(backend._current.call_count, 3)
                self.assertEqual(
                    json.loads((case / "gateway-bound.json").read_text()), receipt
                )
                self.assertEqual(
                    json.loads((case / "gateway-created.json").read_text()), receipt
                )
                with self.assertRaises(FileExistsError):
                    backend._bind_gateway_socket(grant)
                bind.assert_called_once()

    def test_root_bound_socket_closes_and_keeps_intent_when_guard_is_lost(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {"attempt_id": "run_" + "a" * 64, "broker_uid": 2005}
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {
                "schema": 4,
                "gateway_uid": 2007,
                "gateway_socket_sha256": "d" * 64,
            }
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.guard = threading.Lock()
            backend._saved = Mock(return_value=case)
            backend._current = Mock(return_value=case)
            backend._saved_scope = Mock(return_value="c" * 64)
            backend._kernel_scope = Mock()
            sock = Mock()
            identity = {
                "path": "/var/lib/sfactory-harness/gw/" + "a" * 64 + ".sock",
                "dev": 1,
                "ino": 2,
            }
            bind = Mock(
                side_effect=lambda *_, on_created: (
                    on_created(identity),
                    (sock, identity),
                )[1]
            )
            ready = {"owner_pid": os.getpid(), "owner_ticks": 44}
            with (
                patch.object(root, "load_gateway_socket", return_value=bind),
                patch.object(
                    root,
                    "check_guard",
                    side_effect=[ready, root.SupervisorRefused("guard lost")],
                ),
                patch.object(root, "_ticks", return_value=44),
                patch.object(
                    root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                ),
            ):
                with self.assertRaises(root.SupervisorRefused):
                    backend._bind_gateway_socket(grant)
                sock.close.assert_called_once_with()
                self.assertTrue((case / "gateway-bind-intent.json").is_file())
                self.assertTrue((case / "gateway-created.json").is_file())
                self.assertFalse((case / "gateway-bound.json").exists())

    def test_root_refuses_socket_without_durable_creation_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {"attempt_id": "run_" + "a" * 64, "broker_uid": 2005}
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {
                "schema": 4,
                "gateway_uid": 2007,
                "gateway_socket_sha256": root.GATEWAY_SOCKET_SHA256,
            }
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.guard = threading.Lock()
            backend._saved = Mock(return_value=case)
            backend._current = Mock(return_value=case)
            backend._saved_scope = Mock(return_value="c" * 64)
            backend._kernel_scope = Mock()
            sock = Mock()
            with (
                patch.object(
                    root,
                    "load_gateway_socket",
                    return_value=Mock(return_value=(sock, {})),
                ),
                patch.object(
                    root,
                    "check_guard",
                    return_value={"owner_pid": os.getpid(), "owner_ticks": 44},
                ),
                patch.object(root, "_ticks", return_value=44),
                patch.object(
                    root, "gateway_bind_lock", return_value=contextlib.nullcontext()
                ),
            ):
                with self.assertRaisesRegex(
                    root.SupervisorRefused, "root_gateway_created_identity_changed"
                ):
                    backend._bind_gateway_socket(grant)
            sock.close.assert_called_once_with()
            self.assertTrue((case / "gateway-bind-intent.json").exists())
            self.assertFalse((case / "gateway-bound.json").exists())

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

    def test_root_check_requires_released_launch_current_scope_and_kernel_validation(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {"attempt_id": "run_" + "a" * 64, "broker_uid": 2005}
            (case / "grant.json").write_text(json.dumps(grant))
            backend = object.__new__(root.RootSupervisor)
            backend.cfg = {
                "schema": 4,
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
            child = {
                "path": "/sys/fs/cgroup/public.slice/gateway",
                "dev": 1,
                "ino": 2,
                "pid": 123,
                "ticks": 99,
            }
            userns = {
                "grant_sha256": root.sha(grant),
                "scope_sha256": "c" * 64,
                "pid": 123,
                "ticks": 99,
                "namespace": {"dev": 3, "ino": 4},
            }
            prepared = {
                "grant_sha256": root.sha(grant),
                "child": child,
                "gate_dev": 5,
                "gate_ino": 6,
                "deadline_ms": 7,
                "namespace": userns,
            }
            release = {
                "grant_sha256": root.sha(grant),
                "prepared_sha256": root.sha(prepared),
            }
            records = {
                "gateway-userns.json": userns,
                "gateway-prepared.json": prepared,
                "gateway-attached.json": {
                    "intent": {
                        "grant_sha256": root.sha(grant),
                        "scope_sha256": "c" * 64,
                        "gateway_uid": 2007,
                    },
                    "child": child,
                },
                "gateway-released.json": release,
                "gateway-release-intent.json": release,
            }
            with (
                patch.object(
                    root, "protected", side_effect=lambda p, *_: p.read_bytes()
                ),
                patch.object(
                    root,
                    "gateway_bind_lock",
                    side_effect=lambda _: contextlib.nullcontext(),
                ),
                patch.object(root, "check_guard") as guard,
                patch.object(root, "inspect_gateway_peer") as inspect,
                patch.object(root, "inspect_prepared_gateway"),
                patch.object(root, "inspect_gateway_user_namespace") as namespace,
                patch.object(root, "_ticks", return_value=44),
            ):
                guard.return_value = {"owner_pid": os.getpid(), "owner_ticks": 44}
                with self.assertRaises(root.SupervisorRefused):
                    backend.gateway_peer_v1(body)
                inspect.assert_not_called()
                for name, value in records.items():
                    (case / name).write_text(json.dumps(value))
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
                for change in ({"pid": 124}, {"start_ticks": 100}):
                    with self.assertRaises(root.SupervisorRefused):
                        backend.gateway_peer_v1(body | change)
                for name, value in records.items():
                    (case / name).write_text("{}")
                    with self.assertRaises(root.SupervisorRefused):
                        backend.gateway_peer_v1(body)
                    (case / name).write_text(json.dumps(value))
                stale_cases = []
                stale = json.loads(json.dumps(records))
                stale["gateway-attached.json"]["intent"]["scope_sha256"] = "d" * 64
                stale_cases.append(stale)
                stale = json.loads(json.dumps(records))
                for name in ("gateway-released.json", "gateway-release-intent.json"):
                    stale[name]["prepared_sha256"] = "d" * 64
                stale_cases.append(stale)
                stale = json.loads(json.dumps(records))
                stale["gateway-userns.json"]["scope_sha256"] = "d" * 64
                stale["gateway-prepared.json"]["namespace"] = stale[
                    "gateway-userns.json"
                ]
                for name in ("gateway-released.json", "gateway-release-intent.json"):
                    stale[name]["prepared_sha256"] = root.sha(
                        stale["gateway-prepared.json"]
                    )
                stale_cases.append(stale)
                for stale in stale_cases:
                    for name, value in stale.items():
                        (case / name).write_text(json.dumps(value))
                    with self.assertRaises(root.SupervisorRefused):
                        backend.gateway_peer_v1(body)
                for name, value in records.items():
                    (case / name).write_text(json.dumps(value))
                namespace.side_effect = root.SupervisorRefused("namespace changed")
                with self.assertRaises(root.SupervisorRefused):
                    backend.gateway_peer_v1(body)
                namespace.side_effect = None
                for schema in (2, 3):
                    backend.cfg["schema"] = schema
                    with self.assertRaises(root.SupervisorRefused):
                        backend.gateway_peer_v1(body)
                backend.cfg["schema"] = 4
                guard.return_value = {"owner_pid": os.getpid(), "owner_ticks": 45}
                with self.assertRaises(root.SupervisorRefused):
                    backend.gateway_peer_v1(body)
                guard.side_effect = root.SupervisorRefused("guard lost")
                with self.assertRaises(root.SupervisorRefused):
                    backend.gateway_peer_v1(body)
                with self.assertRaises(root.SupervisorRefused):
                    backend.gateway_peer_v1(body | {"pid": True})
                self.assertEqual(inspect.call_count, 1)


class GatewayLifetimeTests(unittest.TestCase):
    @contextlib.contextmanager
    def backend(self):
        from contextlib import ExitStack

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            case = Path(directory)
            catalog = case / "catalog"
            catalog.mkdir()
            backend = object.__new__(root.RootSupervisor)
            child = Mock(pid=456)
            child.poll.return_value = None
            grant = {
                "attempt_id": "run_" + "a" * 64,
                "worker_uid": 2001,
                "broker_uid": 2005,
                "cgroup_path": "/sys/fs/cgroup/public-fixture.slice",
            }
            worker = {"pid": 789, "public_fixture": True}
            backend.cfg = {
                "schema": 5,
                "gateway_uid": 2007,
                "gateway_executable_sha256": "e" * 64,
                "gateway_program": str(case / "gateway"),
                "goose": str(case / "goose"),
                "worker_program": str(case / "worker"),
                "worker_program_sha256": "b" * 64,
            }
            for name in ("gateway", "goose", "worker", "relay"):
                (case / name).write_text("public unit fixture")
            grant["relay_path"] = str(case / "relay")
            backend.catalog = catalog
            backend.recipe = {
                "purpose": "public-fixture",
                "goose_sha256": "a" * 64,
                "max_runtime_ms": 180000,
            }
            backend.guard = threading.RLock()
            backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
            backend.gateway_children = {grant["attempt_id"]: child}
            backend._saved = Mock(return_value=case)
            backend._current = Mock(return_value=case)
            backend._saved_scope = Mock(return_value="c" * 64)
            backend._catalog = Mock(
                return_value=(
                    {"factory_task_id": "public-task", "scope": {"generation": "g"}},
                    {},
                )
            )
            backend._launch_gateway = Mock(return_value=(child, {}))
            backend._verify_gateway_launch = Mock()
            backend._inspect = Mock(return_value={"State": {"Running": True}})
            backend._worker = Mock(return_value=worker)
            backend._fence_execution = Mock(
                side_effect=lambda _: root.store(case / "execution-fenced.json", {})
            )
            backend._revoke_spending = Mock(
                side_effect=lambda _: root.store(case / "owner-revoked.json", {})
            )
            body = {
                "grant": grant,
                "prompt": "public fixture",
                "declarations_sha256": "7" * 64,
                "worker_protocol": "unix-json-v1",
            }
            records = {
                "prepare-intent.json": {
                    "attempt": {"profile": "d" * 64},
                    "admission": {},
                },
                "gateway-cold-ready.json": {
                    "pid": child.pid,
                    "start_ticks": 123,
                    "scope_sha256": "c" * 64,
                    "paid_ready": False,
                },
                "gateway-bootstrap.json": {
                    "deadline_ms": int(time.time() * 1000) + 60000
                },
                "gateway-bound.json": {},
            }
            for name, value in records.items():
                root.store(case / name, value)
            root.store(
                catalog / (grant["attempt_id"] + ".launch.json"),
                {
                    "prompt_sha256": hashlib.sha256(
                        body["prompt"].encode()
                    ).hexdigest(),
                    "declarations_sha256": body["declarations_sha256"],
                    "profile_sha256": "d" * 64,
                    "max_output_tokens": 8,
                },
            )
            original_open, original_fstat = os.open, os.fstat
            relay_fd = []

            def open_source(path, flags, *args, **kwargs):
                if str(path) == grant["relay_path"]:
                    fd = original_open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                    relay_fd.append(fd)
                    return fd
                return original_open(path, flags, *args, **kwargs)

            def metadata(fd):
                value = original_fstat(fd)
                if relay_fd and fd == relay_fd[0]:
                    return SimpleNamespace(
                        st_mode=stat.S_IFSOCK | 0o660, st_uid=2005, st_gid=2001
                    )
                return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0)

            for name, replacement in (
                ("protected", lambda p, *a, **k: Path(p).read_bytes()),
                ("start_guard", Mock()),
                ("check_guard", Mock()),
                ("stage_launch_source", lambda fd, path, target, expected: str(target)),
                ("docker_arguments", lambda *a, **k: ["create"]),
                ("gateway_bind_lock", lambda _: contextlib.nullcontext()),
            ):
                stack.enter_context(patch.object(root, name, replacement))
            peer = stack.enter_context(patch.object(root, "inspect_gateway_peer"))
            stack.enter_context(
                patch.object(root.os, "O_PATH", os.O_RDONLY, create=True)
            )
            stack.enter_context(patch.object(root.os, "open", side_effect=open_source))
            stack.enter_context(patch.object(root.os, "fstat", side_effect=metadata))
            yield backend, case, grant, child, worker, body, peer

    def test_start_refuses_gateway_loss_or_deadline_expiry_during_docker_preparation(
        self,
    ):
        for phase in ("image", "create"):
            for failure in ("exited", "expired"):
                with (
                    self.subTest(phase=phase, failure=failure),
                    self.backend() as fixture,
                ):
                    backend, case, grant, child, _, body, _ = fixture
                    calls = []

                    def docker(*args):
                        calls.append(args[0])
                        if args[0] == phase:
                            if failure == "exited":
                                child.poll.return_value = 0
                            else:
                                (case / "gateway-bootstrap.json").write_text(
                                    json.dumps(
                                        {"deadline_ms": int(time.time() * 1000) - 1}
                                    )
                                )
                        return {
                            "info": b"systemd",
                            "image": b'[{"Config":{"Volumes":null}}]',
                            "create": b"f" * 64,
                            "start": b"",
                        }[args[0]]

                    backend._docker = Mock(side_effect=docker)
                    with self.assertRaises(root.SupervisorRefused):
                        backend.start(body)
                    self.assertNotIn("start", calls)
                    if phase == "image":
                        self.assertNotIn("create", calls)
                    self.assertTrue((case / "start-intent.json").exists())
                    self.assertTrue((case / "execution-fenced.json").exists())
                    self.assertTrue((case / "owner-revoked.json").exists())
                    self.assertFalse((case / "cleanup.json").exists())
                    backend._fence_execution.assert_called_once_with(grant)

    def test_live_gateway_allows_worker_start(self):
        with self.backend() as fixture:
            backend, case, _, _, worker, body, _ = fixture
            backend._docker = Mock(
                side_effect=lambda *a: {
                    "info": b"systemd",
                    "image": b'[{"Config":{"Volumes":null}}]',
                    "create": b"f" * 64,
                    "start": b"",
                }[a[0]]
            )
            self.assertEqual(backend.start(body), worker)
            self.assertTrue((case / "container.json").exists())
            backend._fence_execution.assert_not_called()

    def test_observe_running_worker_requires_current_gateway(self):
        for failure in (None, "missing", "launch", "peer"):
            with self.subTest(failure=failure), self.backend() as fixture:
                backend, case, grant, _, worker, _, peer = fixture
                root.store(case / "worker.json", worker)
                if failure == "missing":
                    (case / "gateway-cold-ready.json").unlink()
                elif failure == "launch":
                    backend._verify_gateway_launch.side_effect = root.SupervisorRefused(
                        "launch lost"
                    )
                elif failure == "peer":
                    peer.side_effect = root.SupervisorRefused("peer changed")
                if failure is None:
                    self.assertEqual(
                        backend.observe({"grant": grant, "worker": worker})["state"],
                        "running",
                    )
                    backend._fence_execution.assert_not_called()
                else:
                    with self.assertRaises(root.SupervisorRefused):
                        backend.observe({"grant": grant, "worker": worker})
                    backend._fence_execution.assert_called_once_with(grant)
                    self.assertTrue((case / "stop.json").exists())
                    self.assertTrue((case / "owner-revoked.json").exists())
                    self.assertFalse((case / "finished.json").exists())
