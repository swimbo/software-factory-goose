#!/usr/bin/env python3
"""Gated Root-created user namespace bootstrap; grants no launch authority.

The caller must own the direct child, pin and validate its namespace and maps,
attach it to the attempt cgroup, and independently authorize gateway release.
"""

import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import stat
import sys
import time


class Refused(Exception):
    pass


def require(value):
    if not value:
        raise Refused("gateway_userns_bootstrap_refused")


def number(value, low, high=2**31 - 1):
    return type(value) is int and low <= value <= high


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def ticks(pid):
    return int(
        (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]
    )


def parent(config):
    pid = config["owner_pid"]
    require(os.getppid() == pid and ticks(pid) == config["owner_ticks"])
    fields = dict(
        line.split(":", 1)
        for line in (Path("/proc") / str(pid) / "status").read_text().splitlines()
        if ":" in line
    )
    require(fields.get("Uid", "").split() == ["0"] * 4)


def run(config):
    keys = {
        "uid",
        "broker_gid",
        "owner_pid",
        "owner_ticks",
        "ready_fd",
        "map_fd",
        "helper_fd",
        "helper_config",
        "python",
        "deadline_ms",
    }
    require(sys.platform == "linux" and type(config) is dict and set(config) == keys)
    require(os.getuid() == os.geteuid() == 0)
    uid, broker = config["uid"], config["broker_gid"]
    require(number(uid, 1) and number(broker, 1) and uid != broker)
    require(
        number(config["owner_pid"], 2) and number(config["owner_ticks"], 1, 2**63 - 1)
    )
    require(number(config["deadline_ms"], 1, 2**63 - 1))
    now = time.time_ns() // 1000000
    require(now < config["deadline_ms"] <= now + 180000)
    require(
        type(config["python"]) is str
        and os.path.isabs(config["python"])
        and os.path.normpath(config["python"]) == config["python"]
    )
    require(type(config["helper_config"]) is dict)
    helper = config["helper_config"]
    fds = [config["ready_fd"], config["map_fd"], config["helper_fd"]]
    for key in ("socket_fd", "program_fd", "gate_fd", "ready_fd"):
        require(key in helper)
        fds.append(helper[key])
    require(all(number(fd, 3, 1048575) for fd in fds) and len(set(fds)) == len(fds))
    require(
        helper.get("gateway_uid") == uid
        and helper.get("gateway_gid") == uid
        and helper.get("broker_gid") == broker
    )
    require(
        helper.get("owner_pid") == config["owner_pid"]
        and helper.get("owner_ticks") == config["owner_ticks"]
    )
    require(helper.get("deadline_ms") == config["deadline_ms"])
    for key, access in (("ready_fd", os.O_WRONLY), ("map_fd", os.O_RDONLY)):
        fd = config[key]
        require(
            stat.S_ISFIFO(os.fstat(fd).st_mode)
            and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == access
        )
    seals = (
        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    )
    require(fcntl.fcntl(config["helper_fd"], fcntl.F_GET_SEALS) == seals)
    keep = set(fds)
    for item in os.listdir("/proc/self/fd"):
        fd = int(item)
        if fd >= 3 and fd not in keep:
            try:
                os.close(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(38, 1, 0, 0, 0) == 0)
    require(libc.prctl(4, 0, 0, 0, 0) == 0)
    parent(config)
    require(libc.unshare(0x10000000) == 0)  # CLONE_NEWUSER
    require(os.write(config["ready_fd"], b"N") == 1)
    os.close(config["ready_fd"])
    seconds = min(15.0, (config["deadline_ms"] - time.time_ns() // 1000000) / 1000)
    require(
        seconds > 0
        and select.select([config["map_fd"]], [], [], seconds)[0]
        and os.read(config["map_fd"], 1) == b"M"
    )
    os.close(config["map_fd"])
    parent(config)
    require(time.time_ns() // 1000000 < config["deadline_ms"])

    def mappings(name):
        rows = (Path("/proc/self") / name).read_text().splitlines()
        require(len(rows) <= 3)
        result = [tuple(int(item) for item in row.split()) for row in rows]
        require(all(len(row) == 3 for row in result))
        return sorted(result)

    require(
        mappings("uid_map") == sorted([(0, 0, 1), (uid, uid, 1)])
        and mappings("gid_map")
        == sorted([(0, 0, 1), (uid, uid, 1), (broker, broker, 1)])
    )
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    require(
        status.get("Uid", "").split() == [str(uid)] * 4
        and status.get("Gid", "").split() == [str(uid)] * 4
    )
    require(
        status.get("Groups", "").split() == []
        and status.get("NoNewPrivs", "").strip() == "1"
    )
    require(
        all(
            int(status.get(key, "-1").strip(), 16) == 0
            for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")
        )
    )
    for fd in (
        config["helper_fd"],
        *(helper[key] for key in ("socket_fd", "program_fd", "gate_fd", "ready_fd")),
    ):
        os.set_inheritable(fd, True)
    os.execve(
        config["python"],
        [
            config["python"],
            "-I",
            "-B",
            "/proc/self/fd/" + str(config["helper_fd"]),
            json.dumps(helper, sort_keys=True, separators=(",", ":"), allow_nan=False),
        ],
        {},
    )


def main():
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= 8192)
        run(
            json.loads(
                sys.argv[1],
                object_pairs_hook=unique,
                parse_constant=lambda _: require(False),
            )
        )
    except Exception:
        raise SystemExit("gateway_userns_bootstrap_refused") from None


if __name__ == "__main__":
    main()
