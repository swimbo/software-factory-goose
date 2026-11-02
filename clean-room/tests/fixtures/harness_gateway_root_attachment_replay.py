#!/usr/bin/env python3
"""Disposable joined Root gateway preparation/attachment/release, synthetic authority.

Run in a network-disabled Root container with a writable host cgroup view,
SYS_ADMIN/SETUID/SETGID/SYS_PTRACE and an isolated /var/lib/sfactory-harness.
Sources must be Root-owned and mode 0444. No production constructor, provider,
registry, guard service or wallet authority is supplied by this fixture.
"""

import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch
import uuid

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "crates/execution/harness")
)
import linux_supervisor as root


def main():
    if os.geteuid() != 0 or os.environ.get("SFACTORY_ROOT_ATTACHMENT_FIXTURE") != "1":
        raise RuntimeError("explicit disposable Root fixture required")
    base = Path("/var/lib/sfactory-harness")
    marker = base / "ROOT_ATTACHMENT_DISPOSABLE"
    if marker.read_text() != "ROOT_ATTACHMENT_DISPOSABLE\n":
        raise RuntimeError("isolated fixture marker required")
    target = base / "gateway-target"
    identity = uuid.uuid4().hex + uuid.uuid4().hex
    case = base / identity
    case.mkdir(mode=0o700)
    sockets = base / "gw"
    sockets.mkdir(mode=0o755, exist_ok=True)
    membership = Path("/proc/self/cgroup").read_text().strip().splitlines()
    if (
        len(membership) != 1
        or not membership[0].startswith("0::/")
        or membership == ["0::/"]
    ):
        raise RuntimeError("isolated controller cgroup required")
    group = Path("/sys/fs/cgroup" + membership[0][3:]) / ("fixture-" + identity)
    group.mkdir(mode=0o755)
    info = group.stat()
    grant = {
        "attempt_id": "run_" + identity,
        "broker_uid": 2005,
        "cgroup_path": str(group),
        "cgroup_dev": info.st_dev,
        "cgroup_ino": info.st_ino,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "expires_at_ms": time.time_ns() // 1000000 + 12000,
    }
    backend = object.__new__(root.RootSupervisor)
    backend.cfg = {
        "schema": 4,
        "gateway_uid": 2007,
        "python": sys.executable,
        "gateway_executable_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    }
    backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
    backend.guard = threading.Lock()
    backend._saved = Mock(return_value=case)
    backend._current = Mock(return_value=case)
    backend._saved_scope = Mock(return_value="c" * 64)
    backend._kernel_scope = Mock()
    name = sockets / (identity + ".sock")
    child = gate = None
    program = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    popen = subprocess.Popen

    def capture_spawn(*args, **kwargs):
        # Observe only public fixture output; retain the actual Popen child.
        kwargs.update(stdout=output, stderr=errors)
        return popen(*args, **kwargs)

    try:
        with (
            (case / "stdout").open("wb") as output,
            (case / "stderr").open("wb") as errors,
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bound,
            patch.object(root.subprocess, "Popen", side_effect=capture_spawn),
        ):
            bound.bind(str(name))
            os.chmod(name, 0o660)
            os.chown(name, 2007, 2005)
            info = name.lstat()
            receipt = {
                "intent": {
                    "grant_sha256": root.sha(grant),
                    "scope_sha256": "c" * 64,
                    "gateway_uid": 2007,
                    "broker_gid": 2005,
                },
                "socket": {"path": str(name), "dev": info.st_dev, "ino": info.st_ino},
            }
            for filename in ("gateway-created.json", "gateway-bound.json"):
                root.store(case / filename, receipt)
            with patch.object(
                root,
                "check_guard",
                return_value={
                    "owner_pid": os.getpid(),
                    "owner_ticks": root._ticks(os.getpid()),
                },
            ):
                child, gate, attached = backend._prepare_gateway(grant, bound, program)
                # The real attachment and inspection methods must observe the kernel.
                root.inspect_prepared_gateway(grant, attached, 2007)
                assert Path(attached["path"]).parent == group
                assert (group / "gateway/cgroup.procs").read_text().strip() == str(
                    child.pid
                )
                assert not (case / "gateway-release-intent.json").exists()
                release_gate, gate = gate, None
                backend._release_gateway(grant, child, release_gate)
                assert (case / "gateway-released.json").exists()
            # Observe exec and listener activation without connecting: the target
            # remains live so the cgroup fence, rather than normal exit, must kill it.
            deadline = time.monotonic() + 5
            while True:
                assert child.poll() is None, (
                    child.returncode,
                    (case / "stderr").read_text(),
                    "released gateway exited before fencing",
                )
                executable = Path(f"/proc/{child.pid}/exe")
                try:
                    executable_sha256 = hashlib.sha256(
                        executable.read_bytes()
                    ).hexdigest()
                except FileNotFoundError:
                    raise RuntimeError(
                        (child.wait(timeout=5), (case / "stderr").read_text())
                    ) from None
                if (
                    executable_sha256 == backend.cfg["gateway_executable_sha256"]
                    and (case / "stdout").read_bytes() == b"exec-ready\n"
                ):
                    break
                assert time.monotonic() < deadline, "gateway did not exec"
                time.sleep(0.01)
            backend._fence_execution(grant)
            assert child.wait(timeout=5) == -signal.SIGKILL
            assert "populated 0" in (group / "cgroup.events").read_text().splitlines()
            created = json.loads((case / "gateway-leaf-created.json").read_bytes())
            root.remove_fenced_gateway_leaf(grant, created["leaf"])
            assert not (group / "gateway").exists()
            result = {
                "actual_root_prepare_attach_release": True,
                "actual_namespace_mapping_and_inspection": True,
                "actual_cgroup_attachment_and_fence": True,
                "child_killed_and_joined": True,
                "matching_leaf_removed": True,
                "owned_attempt_cgroup": str(group),
                "controller_cgroup": membership[0],
                "gateway_pid": attached["pid"],
                "gateway_start_ticks": attached["ticks"],
                "gateway_executable_sha256": backend.cfg["gateway_executable_sha256"],
                "synthetic_authority_guard_and_socket_binding": True,
                "production_cleanup_qualified": False,
                "production_admission": False,
                "paid_calls": 0,
                "source_sha256": {
                    p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in (Path(root.__file__), Path(__file__))
                },
            }
    finally:
        os.close(program)
        if gate is not None:
            os.close(gate)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        # This is fixture retirement, not a production handed-socket receipt.
        if (group / "gateway").exists():
            (group / "gateway").rmdir()
        group.rmdir()
        name.unlink(missing_ok=True)
    assert not group.exists() and not name.exists()
    result["owned_attempt_cgroup_absent"] = True
    result["fixture_socket_absent"] = True
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
