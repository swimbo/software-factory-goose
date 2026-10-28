#!/usr/bin/env python3
"""Fixture-only Docker owner-loss controller; never a production brake."""
import json
import select
import subprocess
import sys
import uuid

from docker_owned_escape_spike import IMAGE, LABEL, MAIN


def docker(*args, check=True):
    return subprocess.run(["docker", *args], text=True, capture_output=True, check=check, timeout=8)


class DisposableContainer:
    """Sole fixture owner. Every mutation revalidates full engine ID and unique label."""
    def __init__(self, token=None):
        self.token = token or uuid.uuid4().hex
        if len(self.token) != 32 or any(c not in "0123456789abcdef" for c in self.token):
            raise ValueError("invalid fixture token")
        self.name = "sf-owner-" + self.token
        self.ident = None
        self.closed = False
        self.removed = False

    def inspect(self, target):
        result = docker("inspect", target, check=False)
        if result.returncode:
            if "no such object" in result.stderr.lower():
                return None
            raise RuntimeError("engine inspection unresolved for " + target)
        data = json.loads(result.stdout)
        if len(data) != 1:
            raise RuntimeError("ambiguous container inspection")
        obj = data[0]
        if obj["Config"]["Labels"].get(LABEL) != self.token:
            raise RuntimeError("container label mismatch")
        if self.ident is not None and obj["Id"] != self.ident:
            raise RuntimeError("container ID mismatch")
        return obj

    def start(self):
        if self.closed or self.ident is not None:
            raise RuntimeError("admission closed or already consumed")
        # A timeout may leave an owned, never-started create behind. The name and
        # random label permit cleanup only after a successful identity check.
        result = docker("create", "--name", self.name, "--label", LABEL + "=" + self.token,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "24",
            "--memory", "96m", "--cpus", "0.5", "--user", "65534:65534",
            "--entrypoint", "python3", "--pull", "never", IMAGE, "-u", "-c", MAIN)
        self.ident = result.stdout.strip()
        if len(self.ident) != 64 or any(c not in "0123456789abcdef" for c in self.ident):
            self.ident = None
            raise RuntimeError("invalid create identity")
        obj = self.inspect(self.ident)
        if obj is None:
            raise RuntimeError("created container missing")
        docker("start", self.ident)
        return self.ident

    def cleanup(self):
        self.closed = True
        if self.removed:
            return
        obj = self.inspect(self.ident or self.name)
        if obj is None:
            if self.ident is not None:
                raise RuntimeError("owned container disappeared without cleanup receipt")
            self.removed = True
            return
        if self.ident is None:
            self.ident = obj["Id"]
        if obj["State"]["Running"]:
            docker("kill", self.ident)
        obj = self.inspect(self.ident)
        if obj is None or obj["State"]["Running"]:
            raise RuntimeError("container stop unresolved")
        docker("rm", self.ident)
        if self.inspect(self.ident) is not None:
            raise RuntimeError("container removal unresolved")
        self.removed = True


def main():
    if len(sys.argv) != 2:
        raise ValueError("fixture token required")
    owner = DisposableContainer(sys.argv[1])
    try:
        ident = owner.start()
        print("READY " + ident, flush=True)
        ready, _, _ = select.select([sys.stdin], [], [], 12)
        state = "EOF" if ready and sys.stdin.buffer.read(1) == b"" else "INVALID_OR_TIMEOUT"
        owner.cleanup()
        owner.cleanup()  # idempotent only after a successful, verified removal
        try:
            owner.start()
        except RuntimeError:
            pass
        else:
            raise RuntimeError("admission reopened")
        print("REMOVED " + state, flush=True)
        return 0 if state == "EOF" else 1
    except Exception as exc:
        print("UNRESOLVED " + str(exc), file=sys.stderr, flush=True)
        try:
            owner.cleanup()
        except Exception as cleanup_error:
            print("CLEANUP_UNRESOLVED " + owner.name + " " + str(cleanup_error), file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
