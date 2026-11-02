#!/usr/bin/env python3
"""Unprivileged pre-exec gateway barrier; it grants no launch or spending authority.

A Root launcher must pass only verified descriptors and a frozen grant, attach
this process to the dedicated cgroup, recheck its independent guard, then release
one byte. No provider credentials are accepted by this helper. Production
startup and descendant cleanup are separate, mandatory gates.
"""

import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import sys
import time


class GatewayExecRefused(Exception):
    pass


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def install_transfer_filter():
    """Deny descriptor transfer and alternate asynchronous dispatch syscalls.

    This is one confinement layer, not proof of exclusive UID or whole-system
    socket custody. Unsupported ABIs fail closed before the gateway starts.
    """
    machine = os.uname().machine
    if machine == "x86_64":
        arch = 0xC000003E
        denied = (
            16,
            46,
            47,
            101,
            299,
            307,
            310,
            311,
            312,
            321,
            323,
            425,
            426,
            427,
            438,
        )
    elif machine == "aarch64":
        arch = 0xC00000B7
        denied = (
            29,
            117,
            211,
            212,
            243,
            269,
            270,
            271,
            272,
            280,
            282,
            425,
            426,
            427,
            438,
        )
    else:
        raise GatewayExecRefused("gateway_exec_refused")
    # Validate the audit architecture before interpreting syscall numbers.
    instructions = [
        SockFilter(0x20, 0, 0, 4),
        SockFilter(0x15, 1, 0, arch),
        SockFilter(0x06, 0, 0, 0x80000000),
        SockFilter(0x20, 0, 0, 0),
    ]
    # Reject later unreviewed syscall numbers on either ABI. This also rejects
    # x32 and its historical 512-547 aliases on x86-64.
    instructions.extend(
        (SockFilter(0x35, 0, 1, 512), SockFilter(0x06, 0, 0, 0x80000000))
    )
    for number in denied:
        instructions.extend(
            (SockFilter(0x15, 0, 1, number), SockFilter(0x06, 0, 0, 0x00050001))
        )
    instructions.append(SockFilter(0x06, 0, 0, 0x7FFF0000))
    filters = (SockFilter * len(instructions))(*instructions)
    program = SockFprog(len(instructions), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    require(libc.prctl(22, 2, ctypes.addressof(program), 0, 0) == 0)


def require(value):
    if not value:
        raise GatewayExecRefused("gateway_exec_refused")


def number(value, low, high=2**63 - 1):
    return type(value) is int and low <= value <= high


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def status():
    fields = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    return fields


def process_ticks(pid):
    raw = (Path("/proc") / str(pid) / "stat").read_text()
    return int(raw.rsplit(")", 1)[1].split()[19])


def check_identity(config, *, cgroup):
    fields = status()
    uid = config["gateway_uid"]
    gid = config["gateway_gid"]
    require(
        os.getuid() == os.geteuid() == uid
        and fields.get("Uid", "").split() == [str(uid)] * 4
    )
    require(
        os.getgid() == os.getegid() == gid
        and fields.get("Gid", "").split() == [str(gid)] * 4
        and os.getgroups() == []
    )
    require(fields.get("NoNewPrivs", "").strip() == "1")
    require(
        all(
            int(fields.get(key, "-1").strip(), 16) == 0
            for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")
        )
    )
    require(
        os.getppid() == config["owner_pid"]
        and process_ticks(config["owner_pid"]) == config["owner_ticks"]
    )
    owner = (
        (Path("/proc") / str(config["owner_pid"]) / "status").read_text().splitlines()
    )
    owner_uid = next(
        (line.split(":", 1)[1].split() for line in owner if line.startswith("Uid:")),
        None,
    )
    require(owner_uid == ["0"] * 4)
    require(
        Path("/proc/sys/kernel/random/boot_id").read_text().strip() == config["boot_id"]
    )
    if not cgroup:
        return
    groups = Path("/proc/self/cgroup").read_text().strip().splitlines()
    expected = config["cgroup_path"].removeprefix("/sys/fs/cgroup")
    require(
        len(groups) == 1
        and groups[0].startswith("0::")
        and (groups[0][3:] == expected or groups[0][3:].startswith(expected + "/"))
    )
    fd = os.open(
        config["cgroup_path"],
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(fd)
        require(
            info.st_uid == 0
            and not info.st_mode & 0o022
            and (info.st_dev, info.st_ino)
            == (config["cgroup_dev"], config["cgroup_ino"])
        )
    finally:
        os.close(fd)


def check_program(fd, expected):
    before = os.fstat(fd)
    require(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == 0
        and before.st_nlink == 1
        and not before.st_mode & 0o022
        and not before.st_mode & (stat.S_ISUID | stat.S_ISGID)
        and before.st_mode & 0o111
        and 0 < before.st_size <= 536870912
    )
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        data = os.pread(fd, min(65536, before.st_size - offset), offset)
        require(bool(data))
        if offset == 0:
            require(data.startswith(b"\x7fELF"))
        digest.update(data)
        offset += len(data)
    after = os.fstat(fd)
    require(
        digest.hexdigest() == expected
        and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    )


def check_socket(config):
    path = config["socket_path"]
    info = os.stat(path, follow_symlinks=False)
    require(
        stat.S_ISSOCK(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == config["gateway_uid"]
        and info.st_gid == config["broker_gid"]
        and stat.S_IMODE(info.st_mode) == 0o660
        and (info.st_dev, info.st_ino) == (config["socket_dev"], config["socket_ino"])
    )
    with socket.socket(fileno=os.dup(config["socket_fd"])) as bound:
        require(
            bound.family == socket.AF_UNIX
            and bound.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
            == socket.SOCK_STREAM
            and bound.getsockname() == path
            and bound.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
        )


def run(config):
    keys = {
        "gateway_uid",
        "gateway_gid",
        "owner_pid",
        "owner_ticks",
        "boot_id",
        "cgroup_path",
        "cgroup_dev",
        "cgroup_ino",
        "socket_path",
        "socket_fd",
        "socket_dev",
        "socket_ino",
        "broker_gid",
        "program_fd",
        "program_sha256",
        "gate_fd",
        "ready_fd",
        "deadline_ms",
    }
    require(sys.platform == "linux" and type(config) is dict and set(config) == keys)
    require(
        number(config["gateway_uid"], 1, 2**31 - 1)
        and number(config["gateway_gid"], 1, 2**31 - 1)
        and number(config["broker_gid"], 1, 2**31 - 1)
        and config["broker_gid"] != config["gateway_uid"]
        and number(config["owner_pid"], 2, 2**31 - 1)
        and number(config["owner_ticks"], 1)
    )
    require(
        all(
            number(config[k], 3, 1048575)
            for k in ("socket_fd", "program_fd", "gate_fd", "ready_fd")
        )
        and len({config[k] for k in ("socket_fd", "program_fd", "gate_fd", "ready_fd")})
        == 4
    )
    kept = {config[k] for k in ("socket_fd", "program_fd", "gate_fd", "ready_fd")}
    for item in os.listdir("/proc/self/fd"):
        fd = int(item)
        if fd >= 3 and fd not in kept:
            try:
                os.close(fd)
            except OSError:
                pass
    require(
        number(config["cgroup_dev"], 1)
        and number(config["cgroup_ino"], 1)
        and number(config["socket_dev"], 1)
        and number(config["socket_ino"], 1)
        and number(config["deadline_ms"], 1)
    )
    now = time.time_ns() // 1000000
    require(now < config["deadline_ms"] <= now + 180000)
    for key, access in (("gate_fd", os.O_RDONLY), ("ready_fd", os.O_WRONLY)):
        fd = config[key]
        require(
            stat.S_ISFIFO(os.fstat(fd).st_mode)
            and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == access
        )
    require(
        isinstance(config["program_sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", config["program_sha256"]) is not None
    )
    require(
        isinstance(config["boot_id"], str)
        and re.fullmatch(r"[0-9a-f-]{36}", config["boot_id"]) is not None
    )
    for key, prefix in (
        ("cgroup_path", "/sys/fs/cgroup/"),
        ("socket_path", "/var/lib/sfactory-harness/gw/"),
    ):
        value = config[key]
        require(
            isinstance(value, str)
            and value.startswith(prefix)
            and os.path.normpath(value) == value
            and "\x00" not in value
        )
    require(len(os.fsencode(config["socket_path"])) < 108)
    require(ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) == 0)
    # Protect the pre-exec barrier from same-UID inspection. Linux resets this
    # on a normal exec, so the gateway bootstrap still needs its own custody
    # boundary before any production admission.
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0)
    check_identity(config, cgroup=False)
    check_program(config["program_fd"], config["program_sha256"])
    check_socket(config)
    # CPython can use ioctl for close-on-exec flags, so set these before the
    # inherited filter denies ioctl. No exec occurs before the release gate.
    os.set_inheritable(config["socket_fd"], True)
    os.set_inheritable(config["program_fd"], False)
    install_transfer_filter()
    require(time.time_ns() // 1000000 < config["deadline_ms"])
    require(os.write(config["ready_fd"], b"R") == 1)
    os.close(config["ready_fd"])
    seconds = min(15.0, (config["deadline_ms"] - time.time_ns() // 1000000) / 1000)
    require(
        seconds > 0
        and select.select([config["gate_fd"]], [], [], seconds)[0]
        and os.read(config["gate_fd"], 1) == b"G"
    )
    os.close(config["gate_fd"])
    require(time.time_ns() // 1000000 < config["deadline_ms"])
    check_identity(config, cgroup=True)
    check_program(config["program_fd"], config["program_sha256"])
    check_socket(config)
    require(os.execve in os.supports_fd)
    os.execve(
        config["program_fd"],
        [
            "sfactory-gateway",
            "--socket-fd",
            str(config["socket_fd"]),
            "--socket-path",
            config["socket_path"],
        ],
        {},
    )


def main():
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= 4096)
        run(
            json.loads(
                sys.argv[1],
                object_pairs_hook=unique,
                parse_constant=lambda _: require(False),
            )
        )
    except Exception:
        raise SystemExit("gateway_exec_refused") from None


if __name__ == "__main__":
    main()
