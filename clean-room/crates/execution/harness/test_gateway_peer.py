"""Root gateway process checks; synthetic proc files do not prove Linux custody."""

import contextlib
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
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

    def test_root_launch_composes_bind_prepare_and_one_release(self):
        backend = object.__new__(root.RootSupervisor)
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
        prepared = {
            "grant_sha256": root.sha(grant),
            "child": child,
            "gate_dev": info.st_dev,
            "gate_ino": info.st_ino,
            "deadline_ms": grant["expires_at_ms"],
        }
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
                    patch.object(root.os, "fstat", side_effect=gate_info),
                ):
                    backend._release_gateway(grant, process, writer)
                    self.assertEqual(os.read(reader, 1), b"G")
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
            attached = {
                "path": grant["cgroup_path"] + "/gateway",
                "dev": 3,
                "ino": 4,
                "pid": 456,
                "ticks": 789,
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
            child = Mock(pid=456)
            original_socket = bound.fileno()
            program = os.open(os.devnull, os.O_RDONLY)
            helper = os.open(os.devnull, os.O_RDONLY)

            def spawn(argv, **kwargs):
                self.assertTrue((case / "gateway-spawn-intent.json").exists())
                self.assertEqual(kwargs["user"], 2007)
                self.assertEqual(kwargs["extra_groups"], [])
                self.assertEqual(kwargs["env"], {})
                self.assertIn(original_socket, kwargs["pass_fds"])
                config = json.loads(argv[-1])
                os.write(config["ready_fd"], b"R")
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
                    patch.object(root, "require_no_socket_copy"),
                    patch.object(root.subprocess, "Popen", side_effect=spawn),
                ):
                    actual, gate, receipt = backend._prepare_gateway(
                        grant, bound, program
                    )
                try:
                    self.assertEqual((actual, receipt), (child, attached))
                    self.assertEqual(bound.fileno(), -1)
                    self.assertFalse(os.get_inheritable(gate))
                    self.assertTrue((case / "gateway-prepared.json").exists())
                    backend._attach_gateway.assert_called_once_with(grant, child)
                    child.kill.assert_not_called()
                finally:
                    os.close(gate)
            finally:
                os.close(program)

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
                    patch.object(root, "require_no_socket_copy"),
                    patch.object(root.subprocess, "Popen", return_value=child),
                ):
                    with self.assertRaisesRegex(
                        root.SupervisorRefused, "root_gateway_barrier_not_ready"
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
                            root.remove_unhanded_gateway_socket(
                                "run_" + "a" * 64, identity | {"ino": info.st_ino + 1}
                            )
                        self.assertTrue(path.exists())
                        root.remove_unhanded_gateway_socket("run_" + "a" * 64, identity)
                        self.assertFalse(path.exists())
                        root.remove_unhanded_gateway_socket("run_" + "a" * 64, identity)
                        path.write_text("public fixture")
                        other = path.lstat()
                        with self.assertRaises(root.SupervisorRefused):
                            root.remove_unhanded_gateway_socket(
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
