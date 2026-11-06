#!/usr/bin/env python3
"""Disposable ext4 Root-to-gateway bound socket rehearsal; no production authority."""

import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import traceback

MARKER = "SFACTORY_ROOT_GATEWAY_SOCKET_DISPOSABLE"


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def read(fd):
    require(select.select([fd], [], [], 8)[0], "fixture pipe timeout")
    data = os.read(fd, 1024)
    require(data, "fixture pipe closed")
    return data


def as_uid(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def inside():
    require(
        os.geteuid() == 0 and Path("/" + MARKER).read_text() == MARKER + "\n",
        "fixture marker changed",
    )
    sys.path.insert(0, "/code")
    from linux_gateway_socket import ROOT, bind_gateway_socket
    from linux_supervisor import (
        RootSupervisor,
        SupervisorRefused,
        gateway_socket_absent,
        remove_gateway_socket,
        sha,
        store,
    )
    from protected_spending_control import ControlRefused

    parent = ROOT
    parent.mkdir(parents=True, mode=0o755)
    parent.parent.chmod(0o755)
    parent.chmod(0o777)
    try:
        bind_gateway_socket("a" * 64, 2007, 2005, on_created=lambda _: None)
    except ControlRefused:
        pass
    else:
        raise RuntimeError("writable socket parent accepted")
    parent.chmod(0o755)
    require(not list(parent.iterdir()), "invalid parent created a socket")
    for invalid in ("bad", "A" * 64):
        try:
            bind_gateway_socket(invalid, 2007, 2005, on_created=lambda _: None)
        except ControlRefused:
            pass
        else:
            raise RuntimeError("invalid attempt digest accepted")
    identities = []
    bound, identity = bind_gateway_socket(
        "a" * 64, 2007, 2005, on_created=identities.append
    )
    require(identities == [identity], "creation callback identity changed")
    process = None
    broker = None
    read_fd, write_fd = os.pipe()
    try:
        require(
            bound.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0,
            "Root listened",
        )
        try:
            bind_gateway_socket("a" * 64, 2007, 2005, on_created=lambda _: None)
        except ControlRefused:
            pass
        else:
            raise RuntimeError("existing socket replaced")
        process = subprocess.Popen(
            [
                "/opt/fixture-bound-test",
                "-test.run=^TestFactoryGatewayBoundCrossUIDChild$",
                "-test.timeout=10s",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(bound.fileno(),),
            preexec_fn=lambda: as_uid(2007),
            env={
                "SFACTORY_BOUND_CROSS_UID_CHILD": "1",
                "SFACTORY_BOUND_SOCKET_FD": str(bound.fileno()),
                "SFACTORY_BOUND_SOCKET_PATH": identity["path"],
            },
        )
        bound.close()
        require(read(process.stdout.fileno()) == b"ready\n", "Go gateway not ready")
        broker = os.fork()
        if broker == 0:
            try:
                os.close(read_fd)
                as_uid(2005)
                from gateway_transport import PrivateGatewayClient

                client = PrivateGatewayClient(
                    identity["path"], gateway_uid=2007, broker_uid=2005, owner="fixture"
                )
                require(
                    client.identity == (identity["dev"], identity["ino"]),
                    "broker socket identity changed",
                )
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                    conn.connect(identity["path"])
                    pid, uid, gid = struct.unpack(
                        "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    )
                    require(
                        client._check_path() == client.identity,
                        "broker socket path changed",
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
        require(os.waitstatus_to_exitcode(status) == 0, "broker fixture failed")
        require(
            peer["pid"] == process.pid and peer["uid"] == 2007,
            "gateway peer identity changed",
        )
        require(process.wait(timeout=10) == 0, "gateway fixture failed")
        try:
            bind_gateway_socket("a" * 64, 2007, 2005, on_created=lambda _: None)
        except ControlRefused:
            pass
        else:
            raise RuntimeError("completed socket was silently replaced")
        unhanded = []
        pending, pending_identity = bind_gateway_socket(
            "b" * 64, 2007, 2005, on_created=unhanded.append
        )
        pending.close()
        require(unhanded == [pending_identity], "unhanded identity changed")
        try:
            remove_gateway_socket(
                "run_" + "b" * 64,
                pending_identity | {"ino": pending_identity["ino"] + 1},
            )
        except SupervisorRefused:
            pass
        else:
            raise RuntimeError("mismatched socket inode removed")
        require(
            not gateway_socket_absent("run_" + "b" * 64),
            "mismatched socket disappeared",
        )
        remove_gateway_socket("run_" + "b" * 64, pending_identity)
        remove_gateway_socket("run_" + "b" * 64, pending_identity)
        require(gateway_socket_absent("run_" + "b" * 64), "unhanded socket remains")

        def interrupted(_):
            raise KeyboardInterrupt("fixture callback failure")

        try:
            bind_gateway_socket("c" * 64, 2007, 2005, on_created=interrupted)
        except KeyboardInterrupt:
            pass
        else:
            raise RuntimeError("callback interruption accepted")
        require(
            not gateway_socket_absent("run_" + "c" * 64),
            "ambiguous socket silently removed",
        )
        case = Path("/var/lib/sfactory-harness/root-case")
        case.mkdir(mode=0o700)
        grant = {"attempt_id": "run_" + "d" * 64, "broker_uid": 2005}
        intent = {
            "grant_sha256": sha(grant),
            "scope_sha256": "e" * 64,
            "gateway_uid": 2007,
            "broker_gid": 2005,
        }
        store(case / "gateway-bind-intent.json", intent)

        def durable_created(value):
            store(case / "gateway-created.json", {"intent": intent, "socket": value})

        pending, _ = bind_gateway_socket(
            "d" * 64, 2007, 2005, on_created=durable_created
        )
        pending.close()
        supervisor = object.__new__(RootSupervisor)
        supervisor.cfg = {"schema": 4, "gateway_uid": 2007}
        supervisor._saved = lambda _: case
        supervisor._saved_scope = lambda _: "e" * 64
        supervisor._fence_execution = lambda _: None
        supervisor._kernel_scope = lambda *_args, **_kwargs: None
        supervisor._docker = lambda *_args: b""
        supervisor._cleanup(grant)
        supervisor._cleanup(grant)
        require(
            gateway_socket_absent(grant["attempt_id"]),
            "Root cleanup did not remove owned socket",
        )
        require(
            (case / "gateway-absent.json").is_file()
            and (case / "cleanup.json").is_file(),
            "Root cleanup receipts missing",
        )
        print(
            json.dumps(
                {
                    "root_bound_nonlistening": True,
                    "untrusted_parent_denied": True,
                    "replay_denied": True,
                    "broker_path_check": True,
                    "gateway_peer_uid": peer["uid"],
                    "gateway_peer_pid_matches": True,
                    "gateway_go_activation": True,
                    "unhanded_inode_cleanup": True,
                    "ambiguous_callback_socket_retained": True,
                    "root_cleanup_with_synthetic_fence_and_daemon": True,
                    "fixture_only": True,
                    "paid_calls": 0,
                    "production_admission": False,
                }
            ),
            flush=True,
        )
    finally:
        bound.close()
        if broker is not None:
            try:
                os.kill(broker, signal.SIGKILL)
            except ProcessLookupError:
                pass
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


def outer():
    require(
        sys.platform == "linux" and os.geteuid() == 0 and os.environ.get(MARKER) == "1",
        "isolated fixture required",
    )
    group = Path("/proc/self/cgroup").read_text().strip().splitlines()
    require(
        len(group) == 1 and group[0].startswith("0::") and group[0] != "0::/",
        "isolated cgroup required",
    )
    require(len(sys.argv) == 2, "fixture rootfs required")
    root = Path(sys.argv[1])
    require(
        root.is_absolute()
        and root.is_dir()
        and not root.is_symlink()
        and (root / MARKER).read_text() == MARKER + "\n",
        "fixture rootfs invalid",
    )
    require(
        not (root / "code").exists()
        and not (root / "var/lib/sfactory-harness").exists(),
        "fixture rootfs already attempted",
    )
    source = Path(__file__).resolve().parents[2] / "crates/execution/harness"
    shutil.copytree(source, root / "code", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(__file__, root / "opt/root-gateway-socket.py")
    os.chroot(root)
    os.chdir("/")
    os.execv(
        "/usr/local/bin/python3", ["python3", "/opt/root-gateway-socket.py", "--inside"]
    )


if __name__ == "__main__":
    if sys.argv[1:] == ["--inside"]:
        inside()
    else:
        outer()
