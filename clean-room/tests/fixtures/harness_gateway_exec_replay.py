#!/usr/bin/env python3
"""Isolated cross-UID pre-exec gateway barrier; no production or provider authority."""

import hashlib
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import shutil
import socket
import struct
import subprocess
import sys
import time

SOURCE = Path("/source/clean-room/crates/execution/harness/linux_gateway_exec.py")
TARGET = Path("/var/lib/sfactory-harness/fixture-target")
ROOT = Path("/var/lib/sfactory-harness/gw")


def read(fd, timeout=8):
    if not select.select([fd], [], [], timeout)[0]:
        raise RuntimeError("fixture read timeout")
    return os.read(fd, 1024)


def as_uid(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def ticks(pid):
    raw = (Path("/proc") / str(pid) / "stat").read_text()
    return int(raw.rsplit(")", 1)[1].split()[19])


def run_case(index, action):
    if action == "setuid_program":
        TARGET.chmod(0o4555)
    name = ROOT / ((str(index) * 64) + ".sock")
    kind = (
        socket.SOCK_SEQPACKET if action == "wrong_socket_type" else socket.SOCK_STREAM
    )
    bound = socket.socket(socket.AF_UNIX, kind)
    bound.bind(str(name))
    os.chmod(name, 0o660)
    os.chown(name, 2007, 2005)
    socket_info = name.lstat()
    program = os.open(TARGET, os.O_RDONLY | os.O_CLOEXEC)
    gate_r, gate_w = os.pipe()
    ready_r, ready_w = os.pipe()
    group = Path("/proc/self/cgroup").read_text().strip().splitlines()
    if len(group) != 1 or not group[0].startswith("0::") or group[0] == "0::/":
        raise RuntimeError("isolated cgroup required")
    group_path = "/sys/fs/cgroup" + group[0][3:]
    group_info = os.stat(group_path)
    config = {
        "gateway_uid": 2007,
        "gateway_gid": 2008 if action == "wrong_gid" else 2007,
        "owner_pid": os.getpid(),
        "owner_ticks": ticks(os.getpid()),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "cgroup_path": group_path,
        "cgroup_dev": group_info.st_dev,
        "cgroup_ino": group_info.st_ino + (1 if action == "wrong_cgroup" else 0),
        "socket_path": str(name),
        "socket_fd": bound.fileno(),
        "socket_dev": socket_info.st_dev,
        "socket_ino": socket_info.st_ino + (1 if action == "wrong_socket" else 0),
        "broker_gid": 2005,
        "program_fd": program,
        "program_sha256": (
            "0" * 64
            if action == "wrong_program"
            else hashlib.sha256(TARGET.read_bytes()).hexdigest()
        ),
        "gate_fd": gate_r,
        "ready_fd": ready_w,
        "deadline_ms": time.time_ns() // 1000000
        + (-1 if action == "expired" else 10000),
    }
    proc = None
    try:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                str(SOURCE),
                json.dumps(config, separators=(",", ":")),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(bound.fileno(), program, gate_r, ready_w),
            preexec_fn=lambda: as_uid(2007),
            env={},
        )
        bound.close()
        os.close(program)
        program = None
        os.close(gate_r)
        gate_r = None
        os.close(ready_w)
        ready_w = None
        ready = read(ready_r)
        if action in (
            "wrong_program",
            "wrong_gid",
            "expired",
            "setuid_program",
            "wrong_socket",
            "wrong_socket_type",
        ):
            if ready or proc.wait(timeout=5) == 0:
                raise RuntimeError("changed program or identity accepted")
            return
        if ready != b"R":
            proc.wait(timeout=5)
            raise RuntimeError(
                f"barrier did not become ready: {action}: "
                f"{proc.stderr.read().decode(errors='replace')}"
            )
        if select.select([proc.stdout], [], [], 0.1)[0]:
            raise RuntimeError("target ran before release")
        if action == "closed_gate":
            os.close(gate_w)
            gate_w = None
            if proc.wait(timeout=5) == 0 or proc.stdout.read():
                raise RuntimeError("closed gate launched target")
            return
        os.write(gate_w, b"G")
        os.close(gate_w)
        gate_w = None
        if action == "wrong_cgroup":
            if proc.wait(timeout=5) == 0 or proc.stdout.read():
                raise RuntimeError("wrong cgroup launched target")
            return
        if read(proc.stdout.fileno()) != b"exec-ready\n":
            raise RuntimeError("released target did not execute")
        peer_r, peer_w = os.pipe()
        broker = os.fork()
        if broker == 0:
            try:
                os.close(peer_r)
                as_uid(2005)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(name))
                    pid, uid, _ = struct.unpack(
                        "3i",
                        client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
                    )
                    os.write(peer_w, json.dumps({"pid": pid, "uid": uid}).encode())
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(peer_w)
        peer = json.loads(read(peer_r))
        os.close(peer_r)
        _, result = os.waitpid(broker, 0)
        if (
            os.waitstatus_to_exitcode(result) != 0
            or peer != {"pid": proc.pid, "uid": 2007}
            or proc.wait(timeout=5) != 0
        ):
            raise RuntimeError("target peer or completion changed")
    finally:
        bound.close()
        for fd in (program, gate_r, gate_w, ready_r, ready_w):
            if fd is not None:
                os.close(fd)
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            proc.stdout.close()
            proc.stderr.close()
        if action == "setuid_program":
            TARGET.chmod(0o555)


def owner_loss_case():
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError("fixture subreaper unavailable")
    notify_r, notify_w = os.pipe()
    controller = os.fork()
    if controller == 0:
        try:
            os.close(notify_r)
            name = ROOT / ("a" * 64 + ".sock")
            bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            bound.bind(str(name))
            os.chmod(name, 0o660)
            os.chown(name, 2007, 2005)
            socket_info = name.lstat()
            program = os.open(TARGET, os.O_RDONLY | os.O_CLOEXEC)
            gate_r, gate_w = os.pipe()
            ready_r, ready_w = os.pipe()
            group = Path("/proc/self/cgroup").read_text().strip()[3:]
            group_path = "/sys/fs/cgroup" + group
            info = os.stat(group_path)
            config = {
                "gateway_uid": 2007,
                "gateway_gid": 2007,
                "owner_pid": os.getpid(),
                "owner_ticks": ticks(os.getpid()),
                "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "cgroup_path": group_path,
                "cgroup_dev": info.st_dev,
                "cgroup_ino": info.st_ino,
                "socket_path": str(name),
                "socket_fd": bound.fileno(),
                "socket_dev": socket_info.st_dev,
                "socket_ino": socket_info.st_ino,
                "broker_gid": 2005,
                "program_fd": program,
                "program_sha256": hashlib.sha256(TARGET.read_bytes()).hexdigest(),
                "gate_fd": gate_r,
                "ready_fd": ready_w,
                "deadline_ms": time.time_ns() // 1000000 + 10000,
            }
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(SOURCE),
                    json.dumps(config, separators=(",", ":")),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(bound.fileno(), program, gate_r, ready_w),
                preexec_fn=lambda: as_uid(2007),
                env={},
            )
            bound.close()
            os.close(program)
            os.close(gate_r)
            os.close(ready_w)
            if read(ready_r) != b"R":
                raise RuntimeError("owner-loss child not ready")
            os.close(ready_r)
            os.write(notify_w, str(child.pid).encode())
            os.close(notify_w)
            signal.pause()
            os._exit(1)
        except BaseException:
            os._exit(2)
    os.close(notify_w)
    child_pid = None
    pidfd = None
    try:
        child_pid = int(read(notify_r))
        pidfd = os.pidfd_open(child_pid)
        os.kill(controller, signal.SIGKILL)
        os.waitpid(controller, 0)
        controller = None
        poll = select.poll()
        poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if not poll.poll(5000):
            raise RuntimeError("owner loss left pre-exec child running")
        _, result = os.waitpid(child_pid, 0)
        child_pid = None
        if os.waitstatus_to_exitcode(result) == 0:
            raise RuntimeError("owner loss released gateway")
    finally:
        os.close(notify_r)
        if pidfd is not None:
            os.close(pidfd)
        if controller is not None:
            os.kill(controller, signal.SIGKILL)
            os.waitpid(controller, 0)
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child_pid, 0)


def main():
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or os.environ.get("SFACTORY_GATEWAY_EXEC_FIXTURE") != "1"
    ):
        raise RuntimeError("explicit isolated Root fixture required")
    ROOT.mkdir(parents=True, mode=0o755)
    ROOT.chmod(0o755)
    shutil.copyfile("/fixture-target", TARGET)
    TARGET.chmod(0o555)
    for index, action in enumerate(
        (
            "closed_gate",
            "wrong_cgroup",
            "wrong_program",
            "release",
            "wrong_gid",
            "expired",
            "setuid_program",
            "wrong_socket",
            "wrong_socket_type",
        ),
        1,
    ):
        run_case(index, action)
    owner_loss_case()
    print(
        json.dumps(
            {
                "closed_gate_denied": True,
                "wrong_cgroup_denied": True,
                "wrong_program_denied": True,
                "wrong_gid_denied": True,
                "expired_deadline_denied": True,
                "setuid_program_denied": True,
                "wrong_socket_denied": True,
                "wrong_socket_type_denied": True,
                "released_exec_uid_verified": True,
                "owner_loss_before_release_denied": True,
                "actual_cgroup_migration_tested": False,
                "fixture_only": True,
                "paid_calls": 0,
                "production_admission": False,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
