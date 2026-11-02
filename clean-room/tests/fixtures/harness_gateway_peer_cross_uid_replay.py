#!/usr/bin/env python3
"""Isolated Linux cross-UID socket peer test; no provider or production authority."""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import tempfile
import time
import traceback

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "crates/execution/harness")
)
import gateway_custody as custody
import linux_supervisor as root
from test_scope_preimage_v2 import legacy_scope


def receive(fd):
    if not select.select([fd], [], [], 8)[0]:
        raise RuntimeError("fixture pipe timeout")
    value = os.read(fd, 4096)
    if not value:
        raise RuntimeError("fixture pipe closed")
    return value


def main():
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or os.environ.get("SFACTORY_CROSS_UID_FIXTURE") != "1"
    ):
        raise RuntimeError("explicit isolated Root fixture required")
    group = Path("/proc/self/cgroup").read_text().strip().splitlines()
    if len(group) != 1 or not group[0].startswith("0::") or group[0][3:] == "/":
        raise RuntimeError("owned non-root cgroup required")
    exe = Path(sys.executable).resolve(strict=True)
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    pids = []
    with tempfile.TemporaryDirectory(prefix="sfactory-peer-cross-") as directory:
        os.chmod(directory, 0o777)
        name = str(Path(directory) / "socket")
        read_ready, write_ready = os.pipe()
        read_reply, write_reply = os.pipe()
        read_release, write_release = os.pipe()
        broker = os.fork()
        if broker == 0:
            try:
                os.close(read_ready)
                os.close(read_reply)
                os.close(write_release)
                os.setgroups([])
                os.setgid(2005)
                os.setuid(2005)
                with socket.socket(socket.AF_UNIX) as server:
                    server.bind(name)
                    os.chmod(name, 0o666)
                    server.listen(1)
                    server.settimeout(8)
                    os.write(write_ready, b"R")
                    conn, _ = server.accept()
                    with conn:
                        pid, uid, _ = struct.unpack(
                            "3i",
                            conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
                        )
                        fd = custody.gateway_socket_pidfd(conn, pid)
                        if (
                            uid != 2007
                            or fd is None
                            or not custody.gateway_peer_alive(fd)
                        ):
                            raise RuntimeError("cross-UID pidfd unavailable")
                        ticks = custody.gateway_peer_ticks(pid)
                        scope = legacy_scope()
                        scope["route"]["usage_tariff_sha256"] = "a" * 64
                        digest = root.factory_scope_digest(scope)
                        binding = {
                            "schema": 1,
                            "owner": "owner",
                            "attempt_id": "run_" + "a" * 64,
                            "call_id": "call",
                            "scope_sha256": digest,
                            "route_sha256": scope["route"]["route_sha256"],
                            "request_sha256": "b" * 64,
                            "tariff_sha256": "a" * 64,
                        }
                        call = {
                            "call_id": "call",
                            "scope_sha256": digest,
                            "request_sha256": "b" * 64,
                            "sequence": 0,
                            "request_bytes": 100,
                            "output_tokens": 10,
                        }
                        authority = custody.GatewayAcquisitionAuthority(
                            lambda _: True,
                            lambda b: {
                                "root_sha256": custody.payload_sha256(b),
                                "opened": True,
                            },
                            gateway_uid=2007,
                        )
                        authority.arm_v2(
                            binding,
                            call,
                            scope,
                            1000,
                            verify=lambda p, t, pinned: p == pid
                            and t == ticks
                            and pinned is True,
                        )
                        authority.acquire_v2(
                            uid,
                            {"binding": binding, "call": call},
                            pid=pid,
                            start_ticks=ticks,
                            peer_fd=fd,
                        )
                        request = {
                            "binding": binding,
                            "call": call,
                            "physical_sequence": 0,
                            "physical_sha256": "c" * 64,
                        }
                        if not authority.verify_physical_v2(
                            uid, request, pid=pid, start_ticks=ticks
                        )["verified"]:
                            raise RuntimeError("physical confirmation refused")
                        owned_fd = authority.roots[custody.payload_sha256(binding)][8]
                        os.write(
                            write_reply,
                            (
                                json.dumps({"pid": pid, "uid": uid, "ticks": ticks})
                                + "\n"
                            ).encode(),
                        )
                        receive(read_release)
                        end = time.monotonic() + 3
                        while custody.gateway_peer_alive(fd) and time.monotonic() < end:
                            time.sleep(0.01)
                        if custody.gateway_peer_alive(fd):
                            raise RuntimeError("peer exit not observed")
                        try:
                            authority.verify_physical_v2(
                                uid,
                                request | {"physical_sequence": 1},
                                pid=pid,
                                start_ticks=ticks,
                            )
                        except custody.ControlRefused:
                            pass
                        else:
                            raise RuntimeError("dead peer accepted")
                        authority.retire(binding)
                        try:
                            os.fstat(owned_fd)
                        except OSError:
                            pass
                        else:
                            raise RuntimeError("owned pin not retired")
                        os.close(fd)
                        os.write(write_reply, b"exited\n")
                os._exit(0)
            except BaseException:
                traceback.print_exc()
                os._exit(1)
        pids.append(broker)
        os.close(write_ready)
        os.close(write_reply)
        os.close(read_release)
        gateway = None
        try:
            if receive(read_ready) != b"R":
                raise RuntimeError("broker not ready")
            gateway = os.fork()
            if gateway == 0:
                try:
                    os.setgroups([])
                    os.setgid(2007)
                    os.setuid(2007)
                    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0:
                        os._exit(2)
                    with socket.socket(socket.AF_UNIX) as client:
                        client.connect(name)
                        time.sleep(20)
                finally:
                    os._exit(0)
            pids.append(gateway)
            info = json.loads(receive(read_reply))
            if (
                info["pid"] != gateway
                or info["uid"] != 2007
                or not isinstance(info["ticks"], int)
            ):
                raise RuntimeError("broker peer identity mismatch")
            grant = {"cgroup_path": "/sys/fs/cgroup" + group[0][3:]}
            try:
                root.inspect_gateway_peer(grant, gateway, info["ticks"], 2007, digest)
                root_check = "passed"
            except OSError as error:
                root_check = "os_error_" + str(error.errno)
            os.kill(gateway, signal.SIGTERM)
            os.waitpid(gateway, 0)
            pids.remove(gateway)
            os.write(write_release, b"X")
            if receive(read_reply) != b"exited\n":
                raise RuntimeError("broker did not observe exit")
            _, status = os.waitpid(broker, 0)
            pids.remove(broker)
            if os.waitstatus_to_exitcode(status) != 0:
                raise RuntimeError("broker failed")
            print(
                json.dumps(
                    {
                        "cross_uid_socket_pidfd": True,
                        "cross_uid_authority_verified": True,
                        "dead_peer_denied_and_pin_retired": True,
                        "peer_exit_observed": True,
                        "root_cross_uid_executable_check": root_check,
                        "synthetic_cgroup_only": True,
                        "paid_calls": 0,
                        "production_admission": False,
                    }
                )
            )
        finally:
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            for fd in (read_ready, read_reply, write_release):
                os.close(fd)


if __name__ == "__main__":
    main()
