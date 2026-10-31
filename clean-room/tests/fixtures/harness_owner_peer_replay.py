#!/usr/bin/env python3
"""Disposable ext-family Linux socket custody proof; no live journal or inference.

Run as a trusted Root fixture controller in a network-none pristine Python image,
with only CHOWN, DAC_OVERRIDE, SETUID, SETGID and SYS_CHROOT capabilities. /fixture
must be a fresh ext-family host directory. No production state is mounted.
"""

import json
import os
from pathlib import Path
import shutil
import socket
import sys

BASE = Path("/fixture/rootfs")
CODE = Path("/source/clean-room/crates/execution/harness")
PATH = "/var/lib/sfactory-harness/spending/fixture/spending.sock"


def identity(uid):
    os.setgroups([3002])
    os.setgid(uid)
    os.setuid(uid)


def jailed():
    os.chroot(BASE)
    os.chdir("/")
    sys.path.insert(0, "/code")


def case(name, creator, mode, expected):
    parent = BASE / Path(PATH).relative_to("/").parent
    parent.mkdir(parents=True, exist_ok=True)
    os.chown(parent, 0, 0)
    os.chmod(parent, mode)
    os.chown(parent, 2004, 3002)
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_r)
            jailed()
            if creator != 0:
                identity(creator)
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.settimeout(5)
            server.bind(PATH)
            os.chmod(PATH, 0o660)
            os.chown(PATH, 2004, 3002)
            server.listen(1)
            os.write(ready_w, b"1")
            os.close(ready_w)
            connection, _ = server.accept()
            connection.settimeout(5)
            try:
                if connection.recv(65536):
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnull"
                    )
            finally:
                connection.close()
            os._exit(0)
        except TimeoutError:
            os._exit(0)  # permission-negative client never connects
        except BaseException:
            import traceback

            traceback.print_exc()
            os._exit(1)
    os.close(ready_w)
    assert os.read(ready_r, 1) == b"1", name
    os.close(ready_r)
    result_r, result_w = os.pipe()
    client_pid = os.fork()
    if client_pid == 0:
        os.close(result_r)
        try:
            jailed()
            identity(2005)
            from protected_spending_control import PrivateSpendingClient, ControlRefused

            try:
                client = PrivateSpendingClient(
                    PATH, service_uid=2004, broker_uid=2005, owner="fixture"
                )
                body = dict(
                    call_id="logical",
                    request_sha256="a" * 64,
                    scope_sha256="b" * 64,
                    sequence=0,
                    request_bytes=100,
                    output_tokens=10,
                )
                assert client("begin", body) is None
                outcome = "accepted"
            except ControlRefused as error:
                outcome = str(error)
            os.write(result_w, outcome.encode())
            os._exit(0)
        except BaseException:
            import traceback

            traceback.print_exc()
            os._exit(1)
    os.close(result_w)
    observed = os.read(result_r, 4096).decode()
    os.close(result_r)
    assert os.waitpid(client_pid, 0)[1] == 0, name
    assert os.waitpid(pid, 0)[1] == 0, name
    (BASE / PATH.lstrip("/")).unlink()
    assert observed == expected, (name, observed, expected)
    return dict(case=name, outcome=observed)


def main():
    assert os.geteuid() == 0 and not BASE.exists()
    BASE.mkdir(mode=0o755)
    for directory in ("usr/local", "usr/lib"):
        shutil.copytree("/" + directory, BASE / directory, symlinks=True)
    for directory in ("lib", "lib64"):
        source = Path("/") / directory
        if source.is_symlink():
            (BASE / directory).symlink_to(os.readlink(source))
        elif source.exists():
            shutil.copytree(source, BASE / directory, symlinks=True)
    shutil.copytree(CODE, BASE / "code", ignore=shutil.ignore_patterns("__pycache__"))
    for directory in (
        "var",
        "var/lib",
        "var/lib/sfactory-harness",
        "var/lib/sfactory-harness/spending",
    ):
        (BASE / directory).mkdir(exist_ok=True, mode=0o755)
    # Metadata starts from pristine image; only the leaf becomes service-owned.
    outcomes = [
        case("self-bound-readable-parent", 2004, 0o750, "accepted"),
        case(
            "root-created-chowned-listener", 0, 0o750, "private_spending_peer_changed"
        ),
        case("search-only-parent", 2004, 0o710, "private_spending_path_unavailable"),
    ]
    print(
        json.dumps(
            dict(
                schema=1,
                cases=outcomes,
                live_attempts=0,
                production_admission=False,
                candidate_enabled=False,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
