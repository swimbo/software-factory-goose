#!/usr/bin/env python3
"""Read-only ext4 socket absence replay; no provider or production authority."""

import json
import os
from pathlib import Path
import sys


def main():
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or os.environ.get("SFACTORY_GATEWAY_ABSENCE_FIXTURE") != "1"
    ):
        raise RuntimeError("explicit isolated Root fixture required")
    group = Path("/proc/self/cgroup").read_text().strip().splitlines()
    if len(group) != 1 or not group[0].startswith("0::") or group[0] == "0::/":
        raise RuntimeError("isolated cgroup required")
    root = Path("/fixture")
    marker = "SFACTORY_ROOT_GATEWAY_SOCKET_DISPOSABLE"
    if (root / marker).read_text() != marker + "\n":
        raise RuntimeError("fixture marker changed")
    os.chroot(root)
    os.chdir("/")
    sys.path.insert(0, "/code")
    from linux_supervisor import gateway_socket_absent

    if gateway_socket_absent("run_" + "a" * 64):
        raise RuntimeError("existing socket treated as absent")
    if not gateway_socket_absent("run_" + "b" * 64):
        raise RuntimeError("missing socket not detected")
    print(
        json.dumps(
            {
                "existing_socket_denied": True,
                "missing_socket_detected": True,
                "read_only_fixture": True,
                "paid_calls": 0,
                "production_admission": False,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
