"""Linux credential-free Unix relay component; not a production Runner adapter.

The reviewed root launcher remains the authority for launch, cgroup and deadline.
This transport accepts a protected generic MCP worker protocol. It grants no
admission, pricing, journal, evaluator or candidate authority of its own.
"""

import base64
import os
import platform
import socket
import socketserver
import struct
import threading
import time

from factory_harness import Denied, canonical
from protected_goose_runtime import parse_json

LINUX_GOOSE_SHA256 = "802d1478e6a53ef7c68a56ccfed3aec59eab0afd68aa411ec0c1b516dc5334db"
MAX_REQUEST = 65536


def peer_uid(connection):
    if platform.system() != "Linux":
        raise Denied("linux_peer_identity_unavailable")
    return struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )[1]


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            if peer_uid(self.connection) != self.server.worker_uid:
                raise Denied("worker_identity_mismatch")
            raw = self.rfile.readline(MAX_REQUEST + 1)
            if len(raw) > MAX_REQUEST or not raw.endswith(b"\n"):
                raise Denied("request_overflow")
            value = self.server.dispatch(parse_json(raw))
            response = {"ok": True, "value": value}
        except Exception:
            response = {"ok": False, "value": "protected_attempt_unavailable"}
        try:
            self.wfile.write(canonical(response).encode())
        except OSError:
            pass


class LinuxWorkerRelay(socketserver.ThreadingUnixStreamServer):
    """Kernel-authenticated existing worker protocol, outside its namespaces.

    relay is the existing ModelRelay. Its trusted control performs journaled
    provider sends and tool authorizations; there is no direct HTTP fallback.
    The session owns declarations and exact tool authorization for both variants.
    """

    daemon_threads = True
    block_on_close = False

    def __init__(self, path, *, worker_uid, relay, deadline, cancelled):
        if (
            platform.system() != "Linux"
            or type(worker_uid) is not int
            or not 0 < worker_uid < 2**31
            or worker_uid == os.geteuid()
        ):
            raise Denied("linux_worker_identity_required")
        self.worker_uid, self.relay = worker_uid, relay
        self.deadline, self.cancelled = deadline, cancelled
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(8)
        # UnixServer refuses an existing socket; never unlink another owner.
        super().__init__(os.fspath(path), _Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def dispatch(self, request):
        if request == {"type": "cancel"}:
            self.cancelled.set()
            return {"cancelled": True}
        if not self.lock.acquire(False):
            raise Denied("busy")
        try:
            if self.cancelled.is_set() or time.monotonic() >= self.deadline:
                raise Denied("attempt_closed")
            if not isinstance(request, dict):
                raise Denied("invalid_request")
            if set(request) == {"type", "body"} and request["type"] == "inference":
                return base64.b64encode(self.relay.exchange(request["body"])).decode(
                    "ascii"
                )
            if request == {"type": "list"}:
                return self.relay.session.declarations()
            if (
                set(request) != {"type", "name", "arguments"}
                or request["type"] != "tool"
            ):
                raise Denied("invalid_request")
            if not isinstance(request["name"], str) or not isinstance(
                request["arguments"], dict
            ):
                raise Denied("invalid_arguments")
            return self.relay.tool(request["name"], request["arguments"])
        finally:
            self.lock.release()


class LinuxSessionClient:
    """Credential-free MCP client. Trusted launch fixes broker UID and socket."""

    def __init__(self, path, broker_uid):
        self.path, self.broker_uid = os.fspath(path), broker_uid
        self.cancelled = threading.Event()

    def request(self, value):
        raw = canonical(value).encode() + b"\n"
        if len(raw) > MAX_REQUEST:
            raise Denied("request_overflow")
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(35)
            connection.connect(self.path)
            if peer_uid(connection) != self.broker_uid:
                raise Denied("broker_identity_mismatch")
            connection.sendall(raw)
            data = bytearray()
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > 1048576:
                    raise Denied("response_overflow")
        reply = parse_json(data)
        if (
            not isinstance(reply, dict)
            or set(reply) != {"ok", "value"}
            or reply["ok"] is not True
        ):
            raise Denied("broker_unavailable")
        return reply["value"]

    def declarations(self):
        return self.request({"type": "list"})

    def call(self, name, arguments):
        return self.request({"type": "tool", "name": name, "arguments": arguments})

    def cancel_remote(self):
        return self.request({"type": "cancel"})
