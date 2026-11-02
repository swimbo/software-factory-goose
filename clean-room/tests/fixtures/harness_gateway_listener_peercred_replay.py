#!/usr/bin/env python3
"""Isolated Linux socket-listen credential experiment; no production authority."""

import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import traceback


def read(fd):
    if not select.select([fd], [], [], 5)[0]:
        raise RuntimeError("fixture pipe timeout")
    data = os.read(fd, 1024)
    if not data:
        raise RuntimeError("fixture pipe closed")
    return data


def as_uid(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def experiment(parent_listens):
    children = []
    with tempfile.TemporaryDirectory(prefix="sfactory-peercred-") as directory:
        os.chmod(directory, 0o777)
        path = str(Path(directory) / "socket")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        os.chmod(path, 0o666)
        if parent_listens:
            server.listen(1)
        ready_r, ready_w = os.pipe()
        reply_r, reply_w = os.pipe()
        try:
            gateway = os.fork()
            if gateway == 0:
                try:
                    os.close(ready_r)
                    os.close(reply_r)
                    os.close(reply_w)
                    as_uid(2007)
                    if not parent_listens:
                        server.listen(1)
                    os.write(ready_w, b"R")
                    conn, _ = server.accept()
                    conn.close()
                    server.close()
                    os._exit(0)
                except BaseException:
                    traceback.print_exc()
                    os._exit(1)
            children.append(gateway)
            os.close(ready_w)
            ready_w = None
            if read(ready_r) != b"R":
                raise RuntimeError("gateway not ready")
            broker = os.fork()
            if broker == 0:
                try:
                    os.close(reply_r)
                    server.close()
                    as_uid(2005)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.connect(path)
                        pid, uid, gid = struct.unpack(
                            "3i",
                            client.getsockopt(
                                socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                            ),
                        )
                        os.write(
                            reply_w,
                            json.dumps({"pid": pid, "uid": uid, "gid": gid}).encode(),
                        )
                    os._exit(0)
                except BaseException:
                    traceback.print_exc()
                    os._exit(1)
            children.append(broker)
            os.close(reply_w)
            reply_w = None
            peer = json.loads(read(reply_r))
            for pid in (broker, gateway):
                _, status = os.waitpid(pid, 0)
                children.remove(pid)
                if os.waitstatus_to_exitcode(status) != 0:
                    raise RuntimeError("fixture child failed")
            return peer
        finally:
            server.close()
            for pid in children:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
            for fd in (ready_r, ready_w, reply_r, reply_w):
                if fd is not None:
                    os.close(fd)


def actual_gateway_activation():
    binary = "/fixture-bound-test"
    if not Path(binary).is_file():
        raise RuntimeError("Go gateway fixture binary required")
    with tempfile.TemporaryDirectory(prefix="sfactory-bound-go-") as directory:
        os.chmod(directory, 0o777)
        path = str(Path(directory) / "socket")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        os.chmod(path, 0o666)
        process = None
        read_fd, write_fd = os.pipe()
        broker = None
        try:
            process = subprocess.Popen(
                [
                    binary,
                    "-test.run=^TestFactoryGatewayBoundCrossUIDChild$",
                    "-test.timeout=10s",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(server.fileno(),),
                preexec_fn=lambda: as_uid(2007),
                env={
                    "SFACTORY_BOUND_CROSS_UID_CHILD": "1",
                    "SFACTORY_BOUND_SOCKET_FD": str(server.fileno()),
                    "SFACTORY_BOUND_SOCKET_PATH": path,
                },
            )
            server.close()
            if read(process.stdout.fileno()) != b"ready\n":
                raise RuntimeError("Go gateway activation not ready")
            broker = os.fork()
            if broker == 0:
                try:
                    os.close(read_fd)
                    as_uid(2005)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.connect(path)
                        pid, uid, gid = struct.unpack(
                            "3i",
                            client.getsockopt(
                                socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                            ),
                        )
                        os.write(
                            write_fd,
                            json.dumps({"pid": pid, "uid": uid, "gid": gid}).encode(),
                        )
                    os._exit(0)
                except BaseException:
                    traceback.print_exc()
                    os._exit(1)
            os.close(write_fd)
            write_fd = None
            peer = json.loads(read(read_fd))
            _, status = os.waitpid(broker, 0)
            broker = None
            if (
                os.waitstatus_to_exitcode(status) != 0
                or peer["uid"] != 2007
                or peer["pid"] != process.pid
            ):
                raise RuntimeError("actual Go gateway credential mismatch")
            if process.wait(timeout=10) != 0:
                raise RuntimeError("actual Go gateway fixture failed")
            return peer
        finally:
            server.close()
            if broker is not None:
                os.kill(broker, signal.SIGKILL)
                os.waitpid(broker, 0)
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                process.stdout.close()
                process.stderr.close()
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)


def main():
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or os.environ.get("SFACTORY_LISTEN_CREDENTIAL_FIXTURE") != "1"
    ):
        raise RuntimeError("explicit isolated Root fixture required")
    group = Path("/proc/self/cgroup").read_text().strip().splitlines()
    if len(group) != 1 or not group[0].startswith("0::") or group[0] == "0::/":
        raise RuntimeError("isolated non-root cgroup required")
    root_listen = experiment(True)
    gateway_listen = experiment(False)
    go_gateway_listen = actual_gateway_activation()
    print(
        json.dumps(
            {
                "root_listen": root_listen,
                "gateway_listen": gateway_listen,
                "go_gateway_listen": go_gateway_listen,
                "fixture_only": True,
                "paid_calls": 0,
                "production_admission": False,
            }
        ),
        flush=True,
    )
    if root_listen["uid"] != 0 or gateway_listen["uid"] != 2007:
        raise RuntimeError("unexpected socket credential semantics")


if __name__ == "__main__":
    main()
