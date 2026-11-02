#!/usr/bin/env python3
"""Disposable user namespace replay of the real gateway exec barrier."""

import errno
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

from harness_apparmor_ptrace_fixture import attack, run_victim

sys.path.insert(0, "/fixture/harness")
import linux_supervisor as root

ROOT = Path("/var/lib/sfactory-harness/gw")
TARGET = Path("/var/lib/sfactory-harness/fixture-target")


def read(fd):
    if not select.select([fd], [], [], 8)[0]:
        raise RuntimeError("fixture read timeout")
    return os.read(fd, 4096)


def ticks(pid):
    return int(
        (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]
    )


def case(index, mode):
    path = ROOT / (str(index) * 64 + ".sock")
    bound = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_SEQPACKET if mode == "wrong_type" else socket.SOCK_STREAM,
    )
    bound.bind(str(path))
    os.chmod(path, 0o660)
    os.chown(path, 2007, 2005)
    path_info = path.stat()
    socket_ino = os.fstat(bound.fileno()).st_ino
    program = os.open(TARGET, os.O_RDONLY)
    gate_r, gate_w = os.pipe()
    ready_r, ready_w = os.pipe()
    ns_r, ns_w = os.pipe()
    map_r, map_w = os.pipe()
    out_r, out_w = os.pipe()
    cgroup = Path("/proc/self/cgroup").read_text().strip()
    if not cgroup.startswith("0::/") or cgroup == "0::/":
        raise RuntimeError("isolated host-visible cgroup required")
    group_path = "/sys/fs/cgroup" + cgroup[3:]
    group_info = os.stat(group_path)
    config = {
        "gateway_uid": 2007,
        "gateway_gid": 2007,
        "broker_gid": 2005,
        "owner_pid": os.getpid(),
        "owner_ticks": ticks(os.getpid()),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "cgroup_path": group_path,
        "cgroup_dev": group_info.st_dev,
        "cgroup_ino": group_info.st_ino,
        "socket_path": str(path),
        "socket_fd": bound.fileno(),
        "socket_dev": path_info.st_dev,
        "socket_ino": path_info.st_ino,
        "program_fd": program,
        "program_sha256": hashlib.sha256(TARGET.read_bytes()).hexdigest(),
        "gate_fd": gate_r,
        "ready_fd": ready_w,
        "deadline_ms": time.time_ns() // 1000000 + 15000,
    }
    with patch.object(
        root, "protected", side_effect=lambda path, mode, expected: path.read_bytes()
    ):
        helper_fd = root.stage_gateway_exec()
        bootstrap_fd = root.stage_gateway_userns()
    bootstrap = {
        "uid": 2007,
        "broker_gid": 2005,
        "owner_pid": config["owner_pid"],
        "owner_ticks": config["owner_ticks"],
        "ready_fd": ns_w,
        "map_fd": map_r,
        "helper_fd": helper_fd,
        "helper_config": config,
        "python": "/usr/bin/python3.13",
        "deadline_ms": config["deadline_ms"],
    }
    child = os.fork()
    if child == 0:
        try:
            for fd in (gate_w, ready_r, ns_r, map_w, out_r):
                os.close(fd)
            os.dup2(out_w, 1)
            for fd in (
                bound.fileno(),
                program,
                gate_r,
                ready_w,
                ns_w,
                map_r,
                helper_fd,
                bootstrap_fd,
            ):
                os.set_inheritable(fd, True)
            os.execve(
                "/usr/bin/python3.13",
                [
                    "/usr/bin/python3.13",
                    "-I",
                    "-B",
                    f"/proc/self/fd/{bootstrap_fd}",
                    json.dumps(bootstrap, separators=(",", ":")),
                ],
                {},
            )
        except BaseException:
            os._exit(1)
    for fd in (gate_r, ready_w, ns_w, map_r, out_w, program, helper_fd, bootstrap_fd):
        os.close(fd)
    bound.close()
    replacement = None
    try:
        if read(ns_r) != b"N":
            raise RuntimeError("namespace child failed")
        proc = Path("/proc") / str(child)
        if mode == "closed_map":
            os.close(map_w)
            map_w = None
            _, status = os.waitpid(child, 0)
            child = None
            if os.waitstatus_to_exitcode(status) == 0 or read(ready_r):
                raise RuntimeError("closed map gate executed helper")
            return
        child_ref, child_ticks = SimpleNamespace(pid=child), ticks(child)
        if mode == "bad_map":
            (proc / "uid_map").write_text("0 0 1\n2007 2008 1\n")
            (proc / "gid_map").write_text("0 0 1\n2005 2005 1\n2007 2007 1\n")
        else:
            identity = root.map_gateway_user_namespace(
                child_ref, child_ticks, 2007, 2005
            )
            try:
                root.map_gateway_user_namespace(child_ref, child_ticks, 2007, 2005)
            except root.SupervisorRefused:
                pass
            else:
                raise RuntimeError("user namespace mapping was repeated")
        os.write(map_w, b"M")
        ready = read(ready_r)
        if mode == "bad_map":
            if ready:
                raise RuntimeError("changed namespace map reached helper")
            _, status = os.waitpid(child, 0)
            child = None
            if os.waitstatus_to_exitcode(status) == 0:
                raise RuntimeError("changed namespace map succeeded")
            return
        if mode == "wrong_type":
            if ready:
                raise RuntimeError("wrong socket type accepted")
            _, status = os.waitpid(child, 0)
            child = None
            if os.waitstatus_to_exitcode(status) == 0:
                raise RuntimeError("wrong socket type exited successfully")
            return
        if ready != b"R":
            raise RuntimeError("gateway helper did not become ready")
        if mode == "closed_gate":
            os.close(gate_w)
            gate_w = None
            _, status = os.waitpid(child, 0)
            child = None
            if os.waitstatus_to_exitcode(status) == 0 or read(out_r):
                raise RuntimeError("closed gate executed target")
            return
        if mode == "replaced_socket":
            path.unlink()
            replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            replacement.bind(str(path))
            os.chmod(path, 0o660)
            os.chown(path, 2007, 2005)
            os.write(gate_w, b"G")
            _, status = os.waitpid(child, 0)
            child = None
            if os.waitstatus_to_exitcode(status) == 0 or read(out_r):
                raise RuntimeError("replaced socket executed target")
            return
        os.write(gate_w, b"G")
        if read(out_r) != b"exec-ready\n":
            raise RuntimeError("gateway target self-tests failed")
        root.inspect_gateway_user_namespace(
            child_ref, child_ticks, 2007, 2005, identity
        )
        for bad_uid, bad_gid, bad_identity in (
            (2007, 2005, identity | {"ino": identity["ino"] + 1}),
            (2007, 2006, identity),
            (2006, 2005, identity),
        ):
            try:
                root.inspect_gateway_user_namespace(
                    child_ref, child_ticks, bad_uid, bad_gid, bad_identity
                )
            except root.SupervisorRefused:
                pass
            else:
                raise RuntimeError("namespace verifier accepted substituted identity")
        fd = None
        for entry in (proc / "fd").iterdir():
            try:
                if os.readlink(entry) == f"socket:[{socket_ino}]":
                    fd = int(entry.name)
                    break
            except FileNotFoundError:
                continue
        if fd is None:
            raise RuntimeError("target listening socket descriptor not found")
        result = attack(child, fd)
        if result != {"duplicate_errno": errno.EPERM, "trace_errno": errno.EPERM}:
            raise RuntimeError("same-UID attacker reached gateway: " + str(result))
        peer_r, peer_w = os.pipe()
        broker = os.fork()
        if broker == 0:
            try:
                os.close(peer_r)
                os.setgroups([])
                os.setgid(2005)
                os.setuid(2005)
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(str(path))
                peer = struct.unpack(
                    "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                os.write(peer_w, json.dumps(peer).encode())
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(peer_w)
        try:
            peer = json.loads(read(peer_r))
            _, broker_status = os.waitpid(broker, 0)
            if os.waitstatus_to_exitcode(broker_status) != 0 or peer[:2] != [
                child,
                2007,
            ]:
                raise RuntimeError("broker peer mismatch")
        finally:
            os.close(peer_r)
        _, status = os.waitpid(child, 0)
        child = None
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError("gateway fixture target failed")
    finally:
        if replacement is not None:
            replacement.close()
        for fd in (gate_w, ready_r, ns_r, map_w, out_r):
            if fd is not None:
                os.close(fd)
        if child is not None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
        path.unlink()


def main():
    if os.geteuid() != 0 or os.environ.get("SFACTORY_USERNS_GATEWAY_FIXTURE") != "1":
        raise RuntimeError("explicit disposable Root fixture required")
    if Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip() != "0":
        raise RuntimeError("existing ptrace-scope zero required")
    if run_victim("", False) != {"duplicate_errno": 0, "trace_errno": 0}:
        raise RuntimeError("same-UID attacker positive control unavailable")
    for index, mode in enumerate(
        (
            "closed_map",
            "bad_map",
            "wrong_type",
            "closed_gate",
            "replaced_socket",
            "release",
        ),
        1,
    ):
        case(index, mode)
    print(
        json.dumps(
            {
                "real_helper_filtered_exec": True,
                "wrong_socket_type_denied": True,
                "closed_gate_denied": True,
                "post_readiness_socket_replacement_denied": True,
                "same_uid_ptrace_pidfd_denied": True,
                "broker_peer_identity_verified": True,
                "root_userns_inspection_verified": True,
                "root_userns_bootstrap_verified": True,
                "root_userns_map_and_pin_verified": True,
                "namespace_remap_denied": True,
                "closed_or_changed_map_denied": True,
                "production_admission": False,
                "paid_calls": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
