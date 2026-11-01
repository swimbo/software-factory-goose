#!/usr/bin/env python3
"""Trusted disposable Root controller for the named-mount component proof.

Run in a network-none image with CHOWN, DAC_OVERRIDE, FOWNER, SETUID and SETGID only.
The fresh case volume uses the same absolute path on host and controller. A
separate credential-free worker checks the resulting read-only file/socket binds.
This does not publish catalogs, admit spending, or qualify the full supervisor.
"""

import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "crates/execution/harness")
)
from linux_supervisor import (
    MAX_LAUNCH_FILE_BYTES,
    SupervisorRefused,
    stage_launch_source,
)


def main():
    base = Path(sys.argv[1])
    assert os.geteuid() == 0 and base.is_dir() and not list(base.iterdir())
    os.chown(base, 0, 0)
    base.chmod(0o755)
    mounts = base / "mounts"
    mounts.mkdir(mode=0o700)
    source = base / "source"
    source.write_bytes(b"pinned-original")
    source.chmod(0o444)
    held = os.open(source, os.O_PATH | os.O_NOFOLLOW)
    try:
        replacement = base / "replacement"
        replacement.write_bytes(b"replaced-path")
        replacement.replace(source)
        expected = hashlib.sha256(b"pinned-original").hexdigest()
        stage_launch_source(held, source, mounts / "input", expected)
        assert (mounts / "input").read_bytes() == b"pinned-original"
        try:
            stage_launch_source(held, source, mounts / "wrong-hash", "a" * 64)
        except SupervisorRefused:
            assert not (mounts / "wrong-hash").exists()
        else:
            raise AssertionError("wrong hash accepted")
    finally:
        os.close(held)
    sparse = base / "oversize"
    with sparse.open("wb") as stream:
        stream.truncate(MAX_LAUNCH_FILE_BYTES + 1)
    held = os.open(sparse, os.O_PATH | os.O_NOFOLLOW)
    try:
        try:
            stage_launch_source(held, sparse, mounts / "oversize", "a" * 64)
        except SupervisorRefused:
            assert not (mounts / "oversize").exists()
        else:
            raise AssertionError("oversize accepted")
    finally:
        os.close(held)
        sparse.unlink()
    program = base / "program"
    program.write_bytes(b"#!/usr/local/bin/python3\nprint('pinned-executable')\n")
    program.chmod(0o755)
    held = os.open(program, os.O_PATH | os.O_NOFOLLOW)
    try:
        stage_launch_source(
            held,
            program,
            mounts / "program",
            hashlib.sha256(program.read_bytes()).hexdigest(),
        )
    finally:
        os.close(held)
    broker = base / "broker"
    broker.mkdir(mode=0o700)
    os.chown(broker, 2005, 2005)
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_r)
            os.setgroups([2001])
            os.setgid(2005)
            os.setuid(2005)
            server = socket.socket(socket.AF_UNIX)
            server.settimeout(30)
            server.bind(str(broker / "relay.sock"))
            os.chmod(broker / "relay.sock", 0o660)
            os.chown(broker / "relay.sock", -1, 2001)
            server.listen(1)
            os.write(ready_w, b"1")
            os.close(ready_w)
            client, _ = server.accept()
            client.sendall(b"public-fixture-pong")
            client.close()
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(ready_w)
    assert os.read(ready_r, 1) == b"1"
    os.close(ready_r)
    relay = broker / "relay.sock"
    held = os.open(relay, os.O_PATH | os.O_NOFOLLOW)
    try:
        stage_launch_source(held, relay, mounts / "relay")
        relay.unlink()
        replacement_socket = socket.socket(socket.AF_UNIX)
        replacement_socket.bind(str(relay))
        try:
            stage_launch_source(held, relay, mounts / "changed-relay")
        except SupervisorRefused:
            assert not (mounts / "changed-relay").exists()
        else:
            raise AssertionError("changed relay accepted")
        replacement_socket.close()
    finally:
        os.close(held)
    (base / "ready.json").write_text(
        json.dumps(
            {
                "file_snapshot_survives_source_replacement": True,
                "wrong_hash_denied": True,
                "oversize_denied": True,
                "changed_socket_denied": True,
                "paid_calls": 0,
                "live_attempts": 0,
                "production_admission": False,
            }
        )
    )
    reaped = False
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished:
                reaped = True
                assert status == 0
                print((base / "ready.json").read_text(), flush=True)
                return
            time.sleep(0.1)
        raise TimeoutError("fixture worker did not connect")
    finally:
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except ProcessLookupError:
                pass
            except ChildProcessError:
                pass


if __name__ == "__main__":
    main()
