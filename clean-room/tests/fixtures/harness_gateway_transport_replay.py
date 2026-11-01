#!/usr/bin/env python3
"""Disposable private gateway protocol proof, not Bifrost or billing evidence.

Root controller capabilities: CHOWN, DAC_OVERRIDE, SETUID, SETGID, SYS_CHROOT,
KILL. All sources/runtime are public and the rootfs must be fresh EXT-family
storage. The fake UID2007 gateway supplies explicit synthetic response hashes.
Only kernel peers, bounded framing, complete byte delivery and refusal are proved.
"""

import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import struct
import sys
import time

BASE = Path(sys.argv[1]) / "rootfs"
CODE = Path(__file__).resolve().parents[2] / "crates/execution/harness"
SOCKET = "/var/lib/sfactory-harness/gateway/socket/service.sock"
GROUP = 3003


def jail(uid):
    os.chroot(BASE)
    os.chdir("/")
    os.setgroups([] if uid == 2001 else [GROUP])
    os.setgid(uid)
    os.setuid(uid)
    sys.path.insert(0, "/code")


def serve(ready):
    import base64
    from factory_harness import canonical
    from protected_spending_control import MAX_SSE

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            self.connection.settimeout(4)
            uid = struct.unpack(
                "3i",
                self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
            )[1]
            assert uid == 2005 and self.path == "/gateway/exchange"
            lengths = self.headers.get_all("Content-Length", [])
            assert len(lengths) == 1 and 0 < int(lengths[0]) <= 131072
            request = json.loads(self.rfile.read(int(lengths[0])))
            case = request["call"]["call_id"]
            if case == "drop":
                self.close_connection = True
                return
            prefix = b'data: {"choices":[{"delta":{"content":"'
            suffix = b'"}}]}\n\ndata: [DONE]\n\n'
            size = MAX_SSE + int(case == "overflow")
            sse = prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix
            value = {
                k: request["call"][k]
                for k in ("call_id", "scope_sha256", "request_sha256")
            }
            value.update(
                physical_manifest_sha256="f" * 64, sse=base64.b64encode(sse).decode()
            )
            if case == "wrong_scope":
                value["scope_sha256"] = "0" * 64
            raw = canonical(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True

    server = Server(SOCKET, Handler)
    os.chown(SOCKET, -1, GROUP)
    os.chmod(SOCKET, 0o660)
    os.write(ready, b"1")
    os.close(ready)
    server.serve_forever(poll_interval=0.1)


def actor(uid, case):
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read)
            jail(uid)
            if case == "worker":
                with socket.socket(socket.AF_UNIX) as connection:
                    try:
                        connection.connect(SOCKET)
                    except PermissionError:
                        output = {"worker_denied_before_http": True}
                    else:
                        raise AssertionError("worker crossed private namespace")
            else:
                from factory_harness import canonical
                from gateway_transport import PrivateGatewayClient
                from protected_spending_control import ControlRefused, binding_digest

                client = PrivateGatewayClient(
                    SOCKET, gateway_uid=2007, broker_uid=2005, owner="fixture"
                )
                body = dict(
                    model="auto",
                    max_tokens=100,
                    stream=True,
                    messages=[dict(role="user", content="x" * 65000)],
                )
                call = dict(
                    call_id=case,
                    scope_sha256="b" * 64,
                    request_sha256=binding_digest(body),
                    sequence=0,
                    request_bytes=len(canonical(body).encode()),
                    output_tokens=100,
                )
                root = dict(
                    schema=1,
                    owner="fixture",
                    attempt_id="run_" + "a" * 64,
                    call_id=case,
                    scope_sha256=call["scope_sha256"],
                    route_sha256="c" * 64,
                    request_sha256=call["request_sha256"],
                    tariff_sha256="d" * 64,
                )
                expiry = time.time_ns() // 1000000 + 4000
                try:
                    response = client.exchange(root, call, body, expiry)
                except ControlRefused as error:
                    assert case in ("drop", "overflow", "wrong_scope")
                    assert str(error) == "gateway_outcome_unknown"
                    output = {"case": case, "refused": True}
                else:
                    assert case == "complete"
                    assert len(response["sse"]) == 1048576
                    assert response["sse"].endswith(b"data: [DONE]\n\n")
                    envelope_bytes = len(
                        canonical(
                            dict(
                                binding=root,
                                call=call,
                                request=body,
                                expires_at_ms=expiry,
                            )
                        ).encode()
                    )
                    assert 65536 < envelope_bytes <= 131072
                    output = dict(
                        case=case,
                        complete_sse_bytes=len(response["sse"]),
                        envelope_bytes=envelope_bytes,
                        logical_request_bytes=call["request_bytes"],
                        sse_sha256=hashlib.sha256(response["sse"]).hexdigest(),
                    )
            os.write(write, json.dumps(output).encode())
            os._exit(0)
        except BaseException:
            import traceback

            traceback.print_exc()
            os._exit(1)
    os.close(write)
    import select

    ready, _, _ = select.select([read], [], [], 10)
    if not ready:
        os.kill(pid, signal.SIGKILL)
    raw = os.read(read, 65536) if ready else b""
    os.close(read)
    assert os.waitpid(pid, 0)[1] == 0, case
    return json.loads(raw)


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
    parent = BASE / Path(SOCKET).parent.relative_to("/")
    parent.mkdir(parents=True, mode=0o750)
    for path in parent.parents:
        if path == BASE:
            break
        os.chmod(path, 0o755)
    os.chown(parent, 2007, GROUP)
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read)
            jail(2007)
            serve(write)
        except BaseException:
            import traceback

            traceback.print_exc()
            os._exit(1)
    os.close(write)
    import select

    ready, _, _ = select.select([read], [], [], 5)
    try:
        assert ready and os.read(read, 1) == b"1", "fixture gateway startup"
        results = [actor(2001, "worker")]
        results.extend(
            actor(2005, case)
            for case in ("complete", "wrong_scope", "overflow", "drop")
        )
        print(
            json.dumps(
                dict(
                    schema=1,
                    component="private_gateway_protocol",
                    results=results,
                    actual_bifrost=False,
                    actual_wallet_or_capture=False,
                    synthetic_gateway_receipt=True,
                    production_admission=False,
                    paid_calls=0,
                    live_attempts=0,
                    candidate_enabled=False,
                )
            )
        )
    finally:
        os.close(read)
        done, _ = os.waitpid(pid, os.WNOHANG)
        if not done:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


if __name__ == "__main__":
    main()
