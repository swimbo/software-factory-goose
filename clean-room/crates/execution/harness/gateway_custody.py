"""Single-use gateway acquisition and bounded durable sanitized capture.

Pure dispatch methods do not authenticate UIDs supplied by arbitrary callers.
PrivateCustodyServer obtains those UIDs from the kernel; Root bootstrap alone
supplies its identities, private paths, tariff and schema profiles. This module
never reserves money, issues leases, dispatches inference or enables a candidate.
"""

import copy
import os
from pathlib import Path
import socket
import socketserver
import sqlite3
import stat
import struct
import threading
import http.server

from factory_harness import canonical
from physical_usage import CaptureBinding, normalize_capture, payload_sha256
from protected_spending_control import (
    ControlRefused,
    PrivateSpendingClient,
    _decode,
    _digest,
    _ext4,
    _integer,
    _keys,
    _no_acl,
)
from usage_rating import UsageRatedCollector

LIMIT = 65536
MAX_ROOTS = 4096
MAX_STORAGE = 128 * 1024 * 1024
ROOT_KEYS = frozenset(CaptureBinding.__dataclass_fields__) - {
    "physical_manifest_sha256"
}


def require(ok, reason):
    if not ok:
        raise ControlRefused(reason)


def root_binding(value):
    require(
        type(value) is dict
        and set(value) in (ROOT_KEYS, ROOT_KEYS | {"physical_manifest_sha256"}),
        "invalid_gateway_binding",
    )
    full = dict(value)
    full.setdefault("physical_manifest_sha256", "0" * 64)
    CaptureBinding(**full).validate()
    return {k: value[k] for k in ROOT_KEYS}


def encoded(value):
    raw = canonical(value)
    require(len(raw.encode()) <= LIMIT, "capture_overflow")
    return raw


class GatewayAcquisitionAuthority:
    """Only the trusted broker arms a reserved call; there is no arm RPC.

    Unknown is recorded before invoking the durable owner. Losing an ack never
    rearms the root. The spending owner's single-use begin remains authoritative
    across this process's loss; no cached true response is returned on replay.
    """

    def __init__(self, begin, open_capture, *, gateway_uid):
        require(_integer(gateway_uid, 1, 2**31 - 1), "gateway_identity_invalid")
        self.begin, self.open_capture, self.uid = begin, open_capture, gateway_uid
        self.roots, self.lock = {}, threading.RLock()

    def arm(self, binding, call):
        require(
            type(binding) is dict and set(binding) == ROOT_KEYS,
            "invalid_gateway_binding",
        )
        root = root_binding(binding)
        require(
            _keys(
                call,
                (
                    "call_id",
                    "scope_sha256",
                    "request_sha256",
                    "sequence",
                    "request_bytes",
                    "output_tokens",
                ),
            )
            and all(
                call[k] == root[k]
                for k in ("call_id", "scope_sha256", "request_sha256")
            )
            and _integer(call["sequence"], 0, 31)
            and _integer(call["request_bytes"], 1, 65536)
            and _integer(call["output_tokens"], 1, 16384),
            "invalid_gateway_call",
        )
        key = payload_sha256(root)
        with self.lock:
            require(
                key not in self.roots and len(self.roots) < MAX_ROOTS,
                "gateway_root_unavailable",
            )
            self.roots[key] = [copy.deepcopy(root), copy.deepcopy(call), "armed"]

    def arm_v2(self, binding, call, scope, root_deadline_ms):
        # The authenticated broker must relay Root's deadline honestly; it is a
        # snapshot, not a signature or a live revocation channel. This adds no
        # spending authority; the gateway independently verifies the scope hash.
        from linux_supervisor import factory_scope_digest

        try:
            require(
                type(scope) is dict
                and type(root_deadline_ms) is int
                and 0 < root_deadline_ms
                <= min(scope["expires_at_ms"], scope["route"]["valid_until_ms"])
                and factory_scope_digest(scope) == binding["scope_sha256"]
                and scope["route"]["route_sha256"] == binding["route_sha256"]
                and scope["route"].get("usage_tariff_sha256")
                == binding["tariff_sha256"]
                and len(encoded(scope).encode()) <= LIMIT,
                "gateway_scope_changed",
            )
        except Exception:
            raise ControlRefused("gateway_scope_changed") from None
        with self.lock:
            self.arm(binding, call)
            self.roots[payload_sha256(binding)].extend(
                (copy.deepcopy(scope), root_deadline_ms)
            )

    def acquire(self, uid, body):
        return self._acquire(uid, body, version=1)

    def acquire_v2(self, uid, body):
        return self._acquire(uid, body, version=2)

    def _acquire(self, uid, body, *, version):
        require(
            uid == self.uid and _keys(body, ("binding", "call")), "gateway_role_denied"
        )
        require(
            type(body["binding"]) is dict and set(body["binding"]) == ROOT_KEYS,
            "invalid_gateway_binding",
        )
        key = payload_sha256(root_binding(body["binding"]))
        with self.lock:
            state = self.roots.get(key)
            require(
                state is not None
                and state[0] == body["binding"]
                and state[1] == body["call"]
                and state[2] == "armed"
                and len(state) == (3 if version == 1 else 5),
                "gateway_root_unavailable",
            )
            state[2] = "unknown"
            try:
                require(
                    self.begin(copy.deepcopy(state[1])) is True, "gateway_begin_unknown"
                )
                ack = self.open_capture(copy.deepcopy(state[0]))
                require(
                    _keys(ack, ("root_sha256", "opened"))
                    and ack["root_sha256"] == key
                    and ack["opened"] is True,
                    "gateway_capture_open_unknown",
                )
            except Exception:
                raise ControlRefused("gateway_acquisition_unknown") from None
            state[2] = "acquired"
            result = {"root_sha256": key, "acquired": True}
            if version == 2:
                result.update(
                    schema=2, scope=copy.deepcopy(state[3]), root_deadline_ms=state[4]
                )
            return result

    def dispatch(self, uid, method, body):
        require(method in ("acquire", "acquire_v2"), "gateway_method_denied")
        return (
            self.acquire_v2(uid, body)
            if method == "acquire_v2"
            else self.acquire(uid, body)
        )


class CaptureStore:
    """SQLite FULL-sync transactions in a bootstrap-protected service directory.

    The SQL store is usable in unprivileged tests; it supplies no path/UID trust.
    Production bootstrap must protect the state directory before construction.
    Only reviewed numeric/hash closures and exactly recomputed audits persist.
    """

    def __init__(
        self,
        path,
        *,
        owner,
        route_sha256,
        tariff,
        profiles,
        components,
        broker_uid,
        gateway_uid,
        collector_uid,
        worker_uid=2001,
    ):
        require(
            len({0, broker_uid, gateway_uid, collector_uid, worker_uid}) == 5
            and all(
                _integer(x, 1, 2**31 - 1)
                for x in (broker_uid, gateway_uid, collector_uid, worker_uid)
            ),
            "capture_roles_invalid",
        )
        require(
            _digest(route_sha256)
            and type(profiles) is tuple
            and type(components) is tuple,
            "capture_policy_invalid",
        )
        rated = UsageRatedCollector(tariff, tariff.sha256(), lambda _: None)
        require(
            1 <= len(profiles) <= 32
            and 1 <= len(components) <= 32
            and len(set(components)) == len(components)
            and all(
                isinstance(c, str) and c and len(c) <= 128 and c.isascii()
                for c in components
            ),
            "capture_policy_invalid",
        )
        seen = set()
        for profile in profiles:
            profile.validate()
            require(
                (profile.provider, profile.model) in rated.rates,
                "capture_policy_invalid",
            )
            for role in profile.roles:
                identity = (profile.provider, profile.model, role)
                require(identity not in seen, "capture_policy_invalid")
                seen.add(identity)
        self.owner, self.route, self.tariff, self.profiles, self.components = (
            owner,
            route_sha256,
            tariff,
            profiles,
            components,
        )
        self.roles = {
            "open": broker_uid,
            "close": gateway_uid,
            "closed": collector_uid,
            "audit": collector_uid,
        }
        self.lock = threading.RLock()
        path = Path(path)
        self.path = path
        try:
            fd = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError:
            pass
        else:
            os.close(fd)
        require(
            stat.S_ISREG(path.lstat().st_mode)
            and path.lstat().st_nlink == 1
            and stat.S_IMODE(path.lstat().st_mode) == 0o600,
            "capture_database_unsafe",
        )
        self.db = sqlite3.connect(path, timeout=1, check_same_thread=False)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute("PRAGMA max_page_count=32768")
            self.db.execute("PRAGMA journal_size_limit=1048576")
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK(id=1), policy TEXT NOT NULL)"
            )
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS roots (id TEXT PRIMARY KEY, binding TEXT NOT NULL, closure TEXT, audit TEXT)"
            )
            policy = payload_sha256(
                dict(
                    owner=owner,
                    route=route_sha256,
                    tariff=tariff.sha256(),
                    profiles=[p.as_dict() for p in profiles],
                    components=components,
                    roles=self.roles,
                    worker_uid=worker_uid,
                )
            )
            with self.db:
                old = self.db.execute("SELECT policy FROM meta WHERE id=1").fetchone()
                require(old is None or old[0] == policy, "capture_policy_changed")
                self.db.execute("INSERT OR IGNORE INTO meta VALUES(1, ?)", (policy,))
        except BaseException:
            self.db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()

    def _root(self, body):
        root = root_binding(body)
        require(
            root["owner"] == self.owner
            and root["route_sha256"] == self.route
            and root["tariff_sha256"] == self.tariff.sha256(),
            "capture_binding_changed",
        )
        return root, payload_sha256(root)

    def dispatch(self, uid, method, body):
        require(
            method in self.roles and uid == self.roles[method], "capture_role_denied"
        )
        encoded(body)
        try:
            with self.lock:
                with self.db:
                    result = self._dispatch(method, body)
                fd = os.open(
                    self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                return result
        except sqlite3.Error:
            raise ControlRefused("capture_persistence_unknown") from None

    def _quota(self, amount, *, new=False):
        count, used = self.db.execute(
            "SELECT count(*), coalesce(sum(length(binding)+coalesce(length(closure),0)+coalesce(length(audit),0)),0) FROM roots"
        ).fetchone()
        require(
            count + int(new) <= MAX_ROOTS and used + amount <= MAX_STORAGE,
            "capture_storage_exhausted",
        )

    def _dispatch(self, method, body):
        require(type(body) is dict, "capture_request_invalid")
        if method == "close":
            require(
                _keys(
                    body,
                    ("binding", "snapshot", "component_calls", "absent_components"),
                ),
                "capture_request_invalid",
            )
        elif method == "audit":
            require(_keys(body, ("binding", "audit")), "capture_request_invalid")
        binding = body["binding"] if method in ("close", "audit") else body
        root, key = self._root(binding)
        row = self.db.execute(
            "SELECT binding, closure, audit FROM roots WHERE id=?", (key,)
        ).fetchone()
        if method == "open":
            require(set(body) == ROOT_KEYS, "invalid_gateway_binding")
            text = encoded(root)
            if row is None:
                self._quota(len(text), new=True)
                self.db.execute("INSERT INTO roots VALUES(?,?,NULL,NULL)", (key, text))
            else:
                require(row[0] == text, "capture_binding_changed")
            return {"root_sha256": key, "opened": True}
        require(row is not None and row[0] == encoded(root), "capture_root_unavailable")
        full = CaptureBinding(**binding)
        full.validate()
        if method == "close":
            normalize_capture(body, full, self.profiles, self.components)
            text = encoded(body)
            if row[1] is None:
                self._quota(len(text))
                self.db.execute("UPDATE roots SET closure=? WHERE id=?", (text, key))
            else:
                require(row[1] == text, "capture_closure_changed")
            return {
                "physical_manifest_sha256": full.physical_manifest_sha256,
                "stored": True,
            }
        require(row[1] is not None, "capture_closure_unavailable")
        envelope = _decode(row[1].encode())
        require(envelope["binding"] == binding, "capture_binding_changed")
        if method == "closed":
            return envelope
        require(_keys(body, ("binding", "audit")), "invalid_usage_audit")
        manifest, usages, _, _ = normalize_capture(
            envelope, full, self.profiles, self.components
        )
        expected = UsageRatedCollector(
            self.tariff, self.tariff.sha256(), lambda c: usages[c.call_id]
        ).collect(manifest)
        expected["capture_sha256"] = full.physical_manifest_sha256
        expected["usage_schema_profiles"] = [p.as_dict() for p in self.profiles]
        expected.pop("audit_sha256")
        expected["audit_sha256"] = payload_sha256(expected)
        text = encoded(body["audit"])
        require(text == encoded(expected), "invalid_usage_audit")
        if row[2] is None:
            self._quota(len(text))
            self.db.execute("UPDATE roots SET audit=? WHERE id=?", (text, key))
        else:
            require(row[2] == text, "capture_audit_changed")
        return {"audit_sha256": expected["audit_sha256"], "stored": True}


class PrivateCaptureOpenClient(PrivateSpendingClient):
    def __call__(self, *_):
        raise ControlRefused("capture_open_role_denied")

    def open(self, binding):
        require(
            os.geteuid() == self.broker_uid
            and root_binding(binding)["owner"] == self.owner
            and set(binding) == ROOT_KEYS,
            "capture_open_role_denied",
        )
        return self._send("open", encoded(binding).encode(), prefix="/capture/")


class ProtectedGatewayAcquisitionAuthority(GatewayAcquisitionAuthority):
    def __init__(
        self, journal, capture, *, gateway_uid, worker_uid=2001, collector_uid=2006
    ):
        require(
            type(journal) is PrivateSpendingClient
            and type(capture) is PrivateCaptureOpenClient
            and journal.owner == capture.owner
            and journal.broker_uid == capture.broker_uid
            and len(
                {
                    0,
                    journal.service_uid,
                    journal.broker_uid,
                    capture.service_uid,
                    gateway_uid,
                    worker_uid,
                    collector_uid,
                }
            )
            == 7,
            "gateway_private_services_invalid",
        )
        self.protected_uid = journal.broker_uid
        self.journal, self.capture = journal, capture
        super().__init__(
            lambda call: journal("begin", call), capture.open, gateway_uid=gateway_uid
        )


class ProtectedCaptureStore(CaptureStore):
    def __init__(self, path, *, service_uid, **policy):
        path = Path(path)
        require(
            os.geteuid() == service_uid
            and service_uid > 0
            and service_uid
            not in (
                policy["broker_uid"],
                policy["gateway_uid"],
                policy["collector_uid"],
                policy.get("worker_uid", 2001),
            )
            and path.is_absolute()
            and ".." not in path.parts,
            "capture_private_state_invalid",
        )
        for parent in (path.parent, *path.parent.parents):
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                require(
                    info.st_uid in (0, service_uid) and info.st_mode & 0o022 == 0,
                    "capture_private_state_invalid",
                )
                if parent == path.parent:
                    require(
                        info.st_uid == service_uid
                        and stat.S_IMODE(info.st_mode) == 0o700,
                        "capture_private_state_invalid",
                    )
                _ext4(fd)
                _no_acl(fd)
            finally:
                os.close(fd)
        for name in (str(path), str(path) + "-wal", str(path) + "-shm"):
            if os.path.lexists(name):
                info = os.lstat(name)
                require(
                    stat.S_ISREG(info.st_mode)
                    and info.st_uid == service_uid
                    and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600,
                    "capture_private_state_invalid",
                )
                _no_acl(name)
        self.protected_uid = service_uid
        super().__init__(path, **policy)


class PrivateCustodyServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Self-created private listener; inherited Root listeners are not accepted."""

    daemon_threads = True
    request_queue_size = 8

    def __init__(self, path, backend, *, service_uid, socket_gid, prefix):
        from physical_settlement import ProtectedUsageSettlement

        require(
            os.geteuid() == service_uid
            and service_uid > 0
            and socket_gid > 0
            and prefix in ("/capture/", "/gateway/", "/settlement/"),
            "custody_service_identity_invalid",
        )
        require(
            (
                prefix == "/capture/"
                and type(backend) is ProtectedCaptureStore
                or prefix == "/gateway/"
                and type(backend) is ProtectedGatewayAcquisitionAuthority
                or prefix == "/settlement/"
                and type(backend) is ProtectedUsageSettlement
            )
            and backend.protected_uid == service_uid,
            "custody_backend_invalid",
        )
        path = Path(path)
        require(path.is_absolute() and ".." not in path.parts, "custody_path_invalid")
        for parent in path.parent.parents:
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                require(
                    info.st_uid in (0, service_uid) and info.st_mode & 0o022 == 0,
                    "custody_path_invalid",
                )
                _ext4(fd)
                _no_acl(fd)
            finally:
                os.close(fd)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require(
                info.st_uid == service_uid
                and info.st_gid == socket_gid
                and stat.S_IMODE(info.st_mode) == 0o750,
                "custody_parent_invalid",
            )
            _ext4(fd)
            _no_acl(fd)
        finally:
            os.close(fd)
        self.backend, self.prefix, self.slots = (
            backend,
            prefix,
            threading.BoundedSemaphore(8),
        )
        super().__init__(str(path), _CustodyHandler)
        os.chown(path, -1, socket_gid)
        os.chmod(path, 0o660)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class _CustodyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def do_POST(self):
        try:
            _, uid, _ = struct.unpack(
                "3i",
                self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
            )
            method = self.path.removeprefix(self.server.prefix)
            require(
                self.path == self.server.prefix + method
                and method
                in (
                    "open",
                    "close",
                    "closed",
                    "audit",
                    "acquire",
                    "acquire_v2",
                    "settle",
                ),
                "custody_method_denied",
            )
            lengths = self.headers.get_all("Content-Length", [])
            require(
                len(lengths) == 1
                and lengths[0].isascii()
                and lengths[0].isdecimal()
                and 0 < int(lengths[0]) <= LIMIT
                and self.headers.get("Transfer-Encoding") is None
                and self.headers.get("Content-Encoding") in (None, "identity")
                and self.headers.get("Content-Type") == "application/json",
                "custody_request_invalid",
            )
            raw = self.rfile.read(int(lengths[0]))
            require(len(raw) == int(lengths[0]), "custody_request_unknown")
            body = _decode(raw)
            value = self.server.backend.dispatch(uid, method, body)
            output, code = encoded(value).encode(), 200
        except Exception:
            output, code = b'{"error":"custody_refused"}', 400
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(output)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(output)
        self.close_connection = True
