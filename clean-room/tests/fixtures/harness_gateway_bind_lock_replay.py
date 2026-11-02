#!/usr/bin/env python3
"""Isolated cross-process Root gateway bind-lock replay; no provider authority."""

import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "crates/execution/harness")
)
from linux_supervisor import SupervisorRefused, gateway_bind_lock

MARKER = "SFACTORY_GATEWAY_BIND_LOCK_FIXTURE"


def main():
    if sys.platform != "linux" or os.geteuid() != 0 or os.environ.get(MARKER) != "1":
        raise RuntimeError("explicit isolated Root fixture required")
    group = Path("/proc/self/cgroup").read_text().strip().splitlines()
    if len(group) != 1 or not group[0].startswith("0::") or group[0] == "0::/":
        raise RuntimeError("isolated cgroup required")
    if len(sys.argv) == 3:
        action, case = sys.argv[1], Path(sys.argv[2])
        if action == "try":
            try:
                with gateway_bind_lock(case):
                    print("acquired", flush=True)
            except SupervisorRefused as error:
                if str(error) != "root_gateway_bind_busy":
                    raise
                print("busy", flush=True)
            return
        if action == "hold":
            with gateway_bind_lock(case):
                print("held", flush=True)
                signal.pause()
            return
        raise RuntimeError("invalid child action")
    if len(sys.argv) != 1:
        raise RuntimeError("invalid fixture arguments")
    with tempfile.TemporaryDirectory(prefix="sfactory-bind-lock-") as directory:
        case = Path(directory)
        env = {MARKER: "1"}
        command = [sys.executable, str(Path(__file__).resolve())]

        def probe():
            result = subprocess.run(
                command + ["try", str(case)],
                env=env,
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            return result.stdout.strip()

        with gateway_bind_lock(case):
            if probe() != "busy":
                raise RuntimeError("cross-process lock was bypassed")
        if probe() != "acquired":
            raise RuntimeError("released lock remained held")
        holder = subprocess.Popen(
            command + ["hold", str(case)],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            if (
                not select.select([holder.stdout], [], [], 5)[0]
                or holder.stdout.readline() != b"held\n"
            ):
                raise RuntimeError("lock holder did not start")
            if probe() != "busy":
                raise RuntimeError("live holder did not exclude peer")
            holder.kill()
            holder.wait(timeout=5)
            if probe() != "acquired":
                raise RuntimeError("dead holder retained lock")
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=5)
            holder.stdout.close()
            holder.stderr.close()
        print(
            '{"cross_process_exclusion":true,"owner_death_releases_lock":true,"fixture_only":true,"paid_calls":0,"production_admission":false}',
            flush=True,
        )


if __name__ == "__main__":
    main()
