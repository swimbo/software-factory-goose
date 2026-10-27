#!/usr/bin/env python3
"""Owned-process falsification canary; not a containment or production stop implementation."""

import os
import signal
import subprocess
import sys


def main():
    # Both processes are direct children and remain unreaped until this test is done.
    # Never signal a numeric PID after reaping it or use a caller-supplied PID.
    leader = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], process_group=0
    )
    escapee = None
    try:
        assert os.getpgid(leader.pid) == leader.pid
        escapee = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import os,time; old=os.getpgrp(); os.setsid(); "
                "print(old,os.getpgrp(),flush=True); time.sleep(30)",
            ],
            process_group=leader.pid,
            stdout=subprocess.PIPE,
            text=True,
        )
        import select

        readable, _, _ = select.select([escapee.stdout], [], [], 5)
        if not readable:
            raise RuntimeError("escapee did not report readiness")
        old_group, new_group = map(int, escapee.stdout.readline().split())
        assert old_group == leader.pid and new_group == escapee.pid
        assert leader.poll() is None and escapee.poll() is None
        os.killpg(leader.pid, signal.SIGKILL)
        leader.wait(timeout=5)
        assert escapee.poll() is None, "escapee unexpectedly died with the old group"
        print("PASS: owned setsid escapee survived killing its former process group")
    finally:
        for child in (escapee, leader):
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                if child.stdout is not None:
                    child.stdout.close()


if __name__ == "__main__":
    main()
