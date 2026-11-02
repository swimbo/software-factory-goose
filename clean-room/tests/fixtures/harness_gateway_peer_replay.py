#!/usr/bin/env python3
"""Read-only Linux peer inspection against one explicitly owned child.

This grants no authority, creates no cgroup, and never contacts a provider.
It does not establish cross-UID or production gateway containment.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "crates/execution/harness")
)
import linux_supervisor as root
import gateway_custody as custody


def no_new_privileges():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        os._exit(125)


def main():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("unprivileged Linux fixture required")
    group = Path("/proc/self/cgroup").read_text().strip().splitlines()
    if len(group) != 1 or not group[0].startswith("0::") or group[0][3:] == "/":
        raise RuntimeError("dedicated fixture cgroup required")
    executable = Path(sys.executable).resolve(strict=True)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    root.require_broker_pid_namespace(os.getpid())
    temporary = tempfile.TemporaryDirectory(prefix="sfactory-peer-")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(Path(temporary.name) / "socket"))
    listener.listen(1)
    listener.settimeout(3)
    script = "import socket,sys,time;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall(b'x');time.sleep(30)"
    child = subprocess.Popen(
        [
            str(executable),
            "-I",
            "-B",
            "-c",
            script,
            str(Path(temporary.name) / "socket"),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        preexec_fn=no_new_privileges,
    )
    peer = None
    peer_fd = None
    try:
        peer, _ = listener.accept()
        pid, uid, _ = struct.unpack(
            "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if (pid, uid) != (child.pid, os.geteuid()):
            raise RuntimeError("kernel peer identity changed")
        peer_fd = custody.gateway_socket_pidfd(peer, child.pid)
        if peer_fd is None or not custody.gateway_peer_alive(peer_fd):
            raise RuntimeError("socket peer pidfd unavailable")
        deadline = time.monotonic() + 3
        while True:
            if child.poll() is not None:
                raise RuntimeError("fixture child exited")
            try:
                if Path(f"/proc/{child.pid}/exe").resolve() == executable:
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("fixture child did not exec")
            time.sleep(0.01)
        ticks = root._ticks(child.pid)
        if custody.gateway_peer_ticks(child.pid) != ticks:
            raise RuntimeError("broker peer start time mismatch")
        grant = {"cgroup_path": "/sys/fs/cgroup" + group[0][3:]}
        root.inspect_gateway_peer(grant, child.pid, ticks, os.geteuid(), digest)
        for changed in (ticks + 1,):
            try:
                root.inspect_gateway_peer(
                    grant, child.pid, changed, os.geteuid(), digest
                )
            except root.SupervisorRefused:
                pass
            else:
                raise RuntimeError("reused process identity accepted")
        child.terminate()
        child.wait(timeout=3)
        if custody.gateway_peer_alive(peer_fd):
            raise RuntimeError("exited peer pidfd remained live")
        print(
            json.dumps(
                {
                    "same_uid_real_proc": True,
                    "same_pid_namespace_verified": True,
                    "broker_start_time_verified": True,
                    "socket_pidfd_live_and_exit_verified": True,
                    "changed_start_time_denied": True,
                    "fixture_cgroup_only": True,
                    "cross_uid_proved": False,
                    "paid_calls": 0,
                    "production_admission": False,
                }
            )
        )
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=3)
        if peer_fd is not None:
            os.close(peer_fd)
        if peer is not None:
            peer.close()
        listener.close()
        temporary.cleanup()


if __name__ == "__main__":
    main()
