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
import subprocess
import sys
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
    child = subprocess.Popen(
        [str(executable), "-I", "-B", "-c", "import time;time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        preexec_fn=no_new_privileges,
    )
    try:
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
        print(
            json.dumps(
                {
                    "same_uid_real_proc": True,
                    "same_pid_namespace_verified": True,
                    "broker_start_time_verified": True,
                    "changed_start_time_denied": True,
                    "fixture_cgroup_only": True,
                    "cross_uid_proved": False,
                    "paid_calls": 0,
                    "production_admission": False,
                }
            )
        )
    finally:
        child.terminate()
        child.wait(timeout=3)


if __name__ == "__main__":
    main()
