"""Protected launch, journal, transport and collector orchestration.

Only the supervisor constructs these objects. The launch service authenticates and
admits root-issued scopes; the collector runs under its separate authenticated
identity and settles the SAME owner journal. Dictionary hashes bind their private
service receipts, never authenticate model claims. No ledger is created here.

Audited usage-rated costs are accepted as a separately labeled performance metric.
Complete production usage capture and Linux launch admission remain unverified,
so live admission stays denied. Rehearsal services identify receipts as synthetic.
"""

import copy
from decimal import Decimal, InvalidOperation, ROUND_CEILING, localcontext
import ctypes
import errno
import http.client
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import threading
import time

from billing_capabilities import assess_receipt_sources, factory_paths
from factory_harness import canonical


MAX_RESPONSE = 32768
MAX_SSE = 1048576
TIMEOUT = 5
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
ATTEMPT = re.compile(r"run_[0-9a-f]{64}\Z")
SOURCE_FIELDS = {
    "call_id",
    "request_sha256",
    "scope_sha256",
    "physical_manifest_sha256",
    "sse",
}
SETTLEMENT_FIELDS = {
    "call_id",
    "request_sha256",
    "scope_sha256",
    "route_sha256",
    "physical_manifest_sha256",
    "billing_receipt_sha256",
    "billed_microusd",
    "source",
    "all_calls_complete",
}


class ControlRefused(Exception):
    """Fixed reason codes only; raw service/provider exceptions never escape."""


def binding_digest(value):
    import hashlib

    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _digest(value):
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _keys(value, expected):
    return type(value) is dict and set(value) == set(expected)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ControlRefused("invalid_service_response")
        result[key] = value
    return result


def _decode(raw):
    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ControlRefused("invalid_service_response")
            ),
        )
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ControlRefused("invalid_service_response") from None


def _no_acl(path_or_fd):
    for attribute in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            if type(path_or_fd) is int:
                os.getxattr(path_or_fd, attribute)
            else:
                os.getxattr(path_or_fd, attribute, follow_symlinks=False)
        except OSError as error:
            if error.errno in (errno.ENODATA,):
                continue
            raise ControlRefused("private_spending_acl_unavailable") from None
        raise ControlRefused("private_spending_acl_denied")


def _ext4(fd):
    buffer = (ctypes.c_long * 64)()
    function = ctypes.CDLL(None, use_errno=True).fstatfs
    function.argtypes = [ctypes.c_int, ctypes.c_void_p]
    function.restype = ctypes.c_int
    if function(fd, ctypes.byref(buffer)) != 0 or buffer[0] != 0xEF53:
        raise ControlRefused("private_spending_filesystem_unverified")


def _rated_usd(value):
    if not isinstance(value, str) or len(value) > 64 or value.startswith("-"):
        raise ControlRefused("invalid_usage_rating")
    try:
        amount = Decimal(value)
    except InvalidOperation:
        raise ControlRefused("invalid_usage_rating") from None
    if (
        not amount.is_finite()
        or not 0 <= amount <= Decimal("0.75")
        or amount.as_tuple().exponent < -18
        or len(amount.as_tuple().digits) > 24
        or format(amount, "f") != value
    ):
        raise ControlRefused("invalid_usage_rating")
    return amount


def _micros(amount):
    with localcontext() as context:
        context.prec = 80
        return int((amount * 1000000).to_integral_value(rounding=ROUND_CEILING))


class PrivateSpendingClient:
    """Linux broker-only HTTP over one pinned private Unix spending ingress.

    Root/service-owned non-writable ext4 ancestors and absent POSIX ACLs mirror
    the factory's reviewed private transport assumptions. Socket group traversal
    must be provisioned for the broker; no caller receives admin/collector RPCs.
    Owner, identities and pathname come only from protected supervisor bootstrap.
    """

    def __init__(self, path, *, service_uid, broker_uid, owner):
        if (
            sys.platform != "linux"
            or not _integer(service_uid, 1, 2**31 - 1)
            or not _integer(broker_uid, 1, 2**31 - 1)
            or service_uid == broker_uid
            or os.geteuid() != broker_uid
            or not isinstance(owner, str)
            or NAME.fullmatch(owner) is None
        ):
            raise ControlRefused("private_spending_identity_unavailable")
        path = Path(path)
        if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
            raise ControlRefused("private_spending_path_unavailable")
        self.path, self.service_uid, self.broker_uid, self.owner = (
            path,
            service_uid,
            broker_uid,
            owner,
        )
        self.identity = self._check_path()

    def _check_path(self):
        fds = []
        try:
            fd = os.open(
                "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            fds.append(fd)
            for part in self.path.parts[1:-1]:
                metadata = os.fstat(fd)
                if (
                    metadata.st_uid not in (0, self.service_uid)
                    or metadata.st_mode & 0o022
                ):
                    raise ControlRefused("private_spending_path_unavailable")
                _ext4(fd)
                # A held descriptor pins this exact ancestor through traversal.
                _no_acl(fd)
                fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=fd,
                )
                fds.append(fd)
            metadata = os.fstat(fd)
            if metadata.st_uid not in (0, self.service_uid) or metadata.st_mode & 0o022:
                raise ControlRefused("private_spending_path_unavailable")
            _ext4(fd)
            _no_acl(fd)
            metadata = os.stat(self.path.parts[-1], dir_fd=fd, follow_symlinks=False)
            if (
                not stat.S_ISSOCK(metadata.st_mode)
                or metadata.st_uid != self.service_uid
                or stat.S_IMODE(metadata.st_mode) != 0o660
            ):
                raise ControlRefused("private_spending_socket_unavailable")
            _no_acl(self.path)
            return metadata.st_dev, metadata.st_ino
        except (OSError, ValueError, TypeError):
            raise ControlRefused("private_spending_path_unavailable") from None
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def __call__(self, method, body):
        if method not in ("reserve", "begin") or os.geteuid() != self.broker_uid:
            raise ControlRefused("private_spending_role_denied")
        if (
            not _keys(
                body,
                (
                    "call_id",
                    "request_sha256",
                    "scope_sha256",
                    "sequence",
                    "request_bytes",
                    "output_tokens",
                ),
            )
            or not isinstance(body["call_id"], str)
            or NAME.fullmatch(body["call_id"]) is None
            or not _digest(body["request_sha256"])
            or not _digest(body["scope_sha256"])
            or not _integer(body["sequence"], 0, 31)
            or not _integer(body["request_bytes"], 1, 65536)
            or not _integer(body["output_tokens"], 1, 16384)
        ):
            raise ControlRefused("invalid_spending_request")
        return self._send(method, canonical(body).encode())

    def _send(
        self,
        method,
        raw,
        prefix="/spending/",
        *,
        request_limit=65536,
        response_limit=MAX_RESPONSE,
        timeout=TIMEOUT,
    ):
        # Callers validate role-specific bodies first. Kernel ingress roles remain
        # the authority; sharing transport never grants another role's handlers.
        if (
            not _integer(request_limit, 1, 131072)
            or not _integer(response_limit, 1, 2 * MAX_SSE)
            or type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or not 0 < timeout <= 180
            or len(raw) > request_limit
            or self._check_path() != self.identity
        ):
            raise ControlRefused("private_spending_socket_changed")
        connection = None
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        expired = threading.Event()

        def interrupt():
            expired.set()
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(timeout, interrupt)
        timer.daemon = True
        timer.start()
        try:
            client.connect(str(self.path))
            _, uid, _ = struct.unpack(
                "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid != self.service_uid or self._check_path() != self.identity:
                raise ControlRefused("private_spending_peer_changed")

            class UnixOnly(http.client.HTTPConnection):
                def connect(self):
                    raise ControlRefused("private_spending_reconnect_denied")

            connection = UnixOnly("localhost", timeout=timeout)
            connection.sock = client
            connection.request(
                "POST",
                prefix + method,
                body=raw,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            response = connection.getresponse()
            lengths = response.headers.get_all("Content-Length", [])
            if (
                response.status != 200
                or len(lengths) != 1
                or response.headers.get("Transfer-Encoding") is not None
                or response.headers.get("Content-Encoding") not in (None, "identity")
                or response.headers.get_content_type() != "application/json"
                or len(lengths[0]) > 10
                or not lengths[0].isascii()
                or not lengths[0].isdecimal()
                or not 0 < int(lengths[0]) <= response_limit
            ):
                raise ControlRefused("spending_outcome_unknown")
            result = response.read(response_limit + 1)
            if expired.is_set() or len(result) != int(lengths[0]):
                raise ControlRefused("spending_outcome_unknown")
            return _decode(result)
        except ControlRefused:
            raise
        except Exception:
            raise ControlRefused("spending_outcome_unknown") from None
        finally:
            timer.cancel()
            timer.join(timeout=TIMEOUT)
            if connection is not None:
                connection.close()
            else:
                client.close()


class JournaledControl:
    """One protected launch scope and one spending journal for every physical call.

    launch_service.admit returns a root-issued, already-journaled scope and checks
    the real lease, policy, predecessor fence and day/task inventory. It also owns
    authorize_tool and close; the broker can never call admin RPCs itself.

    provider_transport.exchange returns bounded SSE plus an immutable CLOSED
    physical manifest reference. collector_service.settle fetches and authenticates
    that complete manifest, obtains the selected provider-billed or audited usage
    evidence, claims its evidence IDs and completes this same call under its collector UID before acknowledging.
    These must be authenticated private services, not worker-supplied callbacks.

    This controller owns no persistent allowance. After a crash, the runner's
    checkpoint requires explicit trusted reconciliation; a new Python instance is
    not permission to replay inference. Interrupted dispatches always stay unknown.
    """

    def __init__(
        self,
        launch_service,
        broker_rpc,
        provider_transport,
        collector_service,
        scope_config,
    ):
        config = copy.deepcopy(scope_config)
        fields = {
            "mode",
            "owner",
            "route_sha256",
            "goose_build",
            "profiles",
            "model",
            "policy_sha256",
            "max_request_bytes",
            "max_output_tokens",
            "tools",
        }
        rated = (
            isinstance(config, dict)
            and config.get("cost_basis") == "audited_usage_rated"
        )
        if rated:
            fields |= {"cost_basis", "tariff_sha256"}
        if (
            not _keys(config, fields)
            or rated
            and not _digest(config["tariff_sha256"])
            or config["mode"] not in ("live", "rehearsal")
            or not isinstance(config["owner"], str)
            or NAME.fullmatch(config["owner"]) is None
            or config["model"] != "auto"
            or not all(
                _digest(config[k])
                for k in ("route_sha256", "goose_build", "policy_sha256")
            )
            or not _keys(config["profiles"], ("baseline", "candidate"))
            or not all(_digest(v) for v in config["profiles"].values())
            or not _integer(config["max_request_bytes"], 1, 65536)
            or not _integer(config["max_output_tokens"], 1, 16384)
            or type(config["tools"]) is not tuple
            or set(config["tools"]) != {"read_file", "write_file", "list_files"}
        ):
            raise ControlRefused("invalid_protected_configuration")
        self.config = config
        self.rated = rated
        self.cost_key = "usage_rated_microusd" if rated else "billed_microusd"
        self.launch, self.rpc, self.provider, self.collector = (
            launch_service,
            broker_rpc,
            provider_transport,
            collector_service,
        )
        self.states = {}
        self.lock = threading.RLock()

    def _validate_attempt(self, attempt):
        c = self.config
        if (
            type(attempt) is not dict
            or not isinstance(attempt.get("attempt_id"), str)
            or ATTEMPT.fullmatch(attempt["attempt_id"]) is None
            or (
                self.rated
                and (
                    attempt.get("cost_basis") != "audited_usage_rated"
                    or attempt.get("tariff_sha256") != c["tariff_sha256"]
                )
            )
            or (
                not self.rated
                and ("cost_basis" in attempt or "tariff_sha256" in attempt)
            )
            or attempt.get("mode") != c["mode"]
            or attempt.get("model") != c["model"]
            or attempt.get("route") != c["route_sha256"]
            or attempt.get("goose_build") != c["goose_build"]
            or attempt.get("budget_owner") != c["owner"]
            or type(attempt.get("budget")) is not int
            or attempt["budget"] != 750000
            or type(attempt.get("daily_cap")) is not int
            or attempt["daily_cap"] != 5000000
            or attempt.get("variant") not in c["profiles"]
            or attempt.get("profile") != c["profiles"][attempt["variant"]]
            or not _digest(attempt.get("config_sha256"))
            or not _digest(attempt.get("suite_sha256"))
        ):
            raise ControlRefused("attempt_binding_mismatch")

    def admit(self, attempt):
        with self.lock:
            self._validate_attempt(attempt)
            attempt = copy.deepcopy(attempt)
            existing = self.states.get(attempt["attempt_id"])
            if existing is not None:
                if (
                    existing["attempt"] != attempt
                    or existing["phase"] != "ready"
                    or existing["closed"]
                ):
                    raise ControlRefused("attempt_unavailable")
                return copy.deepcopy(existing["admission"])
            if self.config["mode"] == "live":
                review = assess_receipt_sources(
                    self.config["route_sha256"], factory_paths()
                )
                if self.rated:
                    review = {
                        "cost_basis": "audited_usage_rated",
                        "tariff_sha256": self.config["tariff_sha256"],
                        "reason": "production_launch_and_complete_usage_capture_unverified",
                    }
                # Documentation coverage is not authentication or live admission.
                # No currently reviewed complete factory contract exists.
                return {
                    "attempt_id": attempt["attempt_id"],
                    "status": "denied",
                    "authority_receipt_sha256": binding_digest(review),
                }
            try:
                grant = self.launch.admit(copy.deepcopy(attempt))
                if not isinstance(grant, dict) or grant.get("status") not in (
                    "allowed",
                    "day_cap",
                    "denied",
                ):
                    raise ControlRefused("invalid_launch_receipt")
                admission = {
                    "attempt_id": attempt["attempt_id"],
                    "status": grant["status"],
                    "authority_receipt_sha256": grant["authority_receipt_sha256"],
                }
                if grant.get("attempt_id") != attempt["attempt_id"] or not _digest(
                    grant.get("authority_receipt_sha256")
                ):
                    raise ControlRefused("invalid_launch_receipt")
                if grant["status"] != "allowed":
                    if not _keys(
                        grant, ("attempt_id", "status", "authority_receipt_sha256")
                    ):
                        raise ControlRefused("invalid_launch_receipt")
                    return admission
                if (
                    not _keys(
                        grant,
                        (
                            "status",
                            "attempt_id",
                            "attempt_sha256",
                            "scope_sha256",
                            "policy_sha256",
                            "owner",
                            "route_sha256",
                            "expires_at_ms",
                            "authority_receipt_sha256",
                        )
                        + (("cost_basis", "tariff_sha256") if self.rated else ()),
                    )
                    or self.rated
                    and (
                        grant.get("cost_basis") != "audited_usage_rated"
                        or grant.get("tariff_sha256") != self.config["tariff_sha256"]
                    )
                    or grant["attempt_sha256"] != binding_digest(attempt)
                    or grant["policy_sha256"] != self.config["policy_sha256"]
                    or grant["owner"] != self.config["owner"]
                    or grant["route_sha256"] != self.config["route_sha256"]
                    or not _digest(grant["scope_sha256"])
                    or not _integer(
                        grant["expires_at_ms"],
                        time.time_ns() // 1000000 + 1,
                        253402300799999,
                    )
                ):
                    raise ControlRefused("invalid_launch_receipt")
                self.states[attempt["attempt_id"]] = {
                    "attempt": attempt,
                    "grant": copy.deepcopy(grant),
                    "admission": admission,
                    "phase": "ready",
                    "next": 0,
                    "receipts": [],
                    "closed": False,
                }
                return copy.deepcopy(admission)
            except ControlRefused:
                raise
            except Exception:
                raise ControlRefused("launch_outcome_unknown") from None

    def _state(self, attempt, *, allow_closed=False):
        self._validate_attempt(attempt)
        state = self.states.get(attempt["attempt_id"])
        if (
            state is None
            or state["attempt"] != attempt
            or state["phase"] == "unknown"
            or (state["closed"] and not allow_closed)
        ):
            raise ControlRefused("attempt_unavailable")
        return state

    def authorize_tool(self, attempt, name, args_sha):
        with self.lock:
            try:
                state = self._state(attempt)
                if (
                    name not in self.config["tools"]
                    or not _digest(args_sha)
                    or time.time_ns() // 1000000 >= state["grant"]["expires_at_ms"]
                ):
                    return False
                receipt = self.launch.authorize_tool(
                    copy.deepcopy(attempt),
                    state["grant"]["scope_sha256"],
                    name,
                    args_sha,
                )
                return (
                    _keys(
                        receipt,
                        (
                            "attempt_sha256",
                            "scope_sha256",
                            "name",
                            "arguments_sha256",
                            "allowed",
                        ),
                    )
                    and receipt["attempt_sha256"] == binding_digest(attempt)
                    and receipt["scope_sha256"] == state["grant"]["scope_sha256"]
                    and receipt["name"] == name
                    and receipt["arguments_sha256"] == args_sha
                    and receipt["allowed"] is True
                )
            except Exception:
                return False

    def exchange(self, attempt, body, sequence):
        with self.lock:
            state = self._state(attempt)
            if (
                state["phase"] != "ready"
                or type(sequence) is not int
                or sequence != state["next"]
                or not 0 <= sequence < 32
                or time.time_ns() // 1000000 >= state["grant"]["expires_at_ms"]
            ):
                raise ControlRefused("dispatch_binding_mismatch")
            body = copy.deepcopy(body)
            allowed = {
                "model",
                "messages",
                "tools",
                "max_tokens",
                "stream",
                "stream_options",
                "temperature",
                "top_p",
                "tool_choice",
                "parallel_tool_calls",
            }
            if (
                type(body) is not dict
                or set(body) - allowed
                or body.get("model") != self.config["model"]
                or body.get("stream") is not True
                or not isinstance(body.get("messages"), list)
                or not isinstance(body.get("tools"), list)
                or not _integer(
                    body.get("max_tokens"), 1, self.config["max_output_tokens"]
                )
            ):
                raise ControlRefused("invalid_provider_request")
            for field, lower, upper in (("temperature", 0, 2), ("top_p", 0, 1)):
                if field in body and (
                    type(body[field]) not in (int, float)
                    or not math.isfinite(body[field])
                    or not lower <= body[field] <= upper
                ):
                    raise ControlRefused("invalid_provider_request")
            if (
                "tool_choice" in body
                and body["tool_choice"] not in ("auto", "none")
                or "parallel_tool_calls" in body
                and type(body["parallel_tool_calls"]) is not bool
                or "stream_options" in body
                and body["stream_options"] != {"include_usage": True}
            ):
                raise ControlRefused("invalid_provider_request")
            try:
                raw = canonical(body).encode()
            except (ValueError, TypeError, UnicodeError, RecursionError):
                raise ControlRefused("invalid_provider_request") from None
            if not 0 < len(raw) <= self.config["max_request_bytes"]:
                raise ControlRefused("provider_request_overflow")
            call = {
                "call_id": "call_"
                + binding_digest(
                    {"attempt": attempt["attempt_id"], "sequence": sequence}
                ),
                "scope_sha256": state["grant"]["scope_sha256"],
                "request_sha256": binding_digest(body),
                "sequence": sequence,
                "request_bytes": len(raw),
                "output_tokens": body["max_tokens"],
            }
            # Sticky before the first potentially committed RPC; no local rollback.
            from gateway_transport import ProtectedGatewayTransport

            gateway_owned = type(self.provider) is ProtectedGatewayTransport
            if gateway_owned:
                self.provider.validate_control(self.config, self.rpc)
            state["phase"] = "unknown"
            try:
                reserved = self.rpc("reserve", copy.deepcopy(call))
                if reserved == "Denied":
                    state["phase"] = "denied"
                    raise ControlRefused("budget_exhausted")
                if reserved != "Reserved":
                    raise ControlRefused("dispatch_outcome_unknown")
                if gateway_owned:
                    response = self.provider.exchange_reserved(
                        copy.deepcopy(attempt),
                        copy.deepcopy(state["grant"]),
                        copy.deepcopy(call),
                        body,
                    )
                else:
                    if self.rpc("begin", copy.deepcopy(call)) is not True:
                        raise ControlRefused("dispatch_outcome_unknown")
                    response = self.provider.exchange(copy.deepcopy(call), body)
                if (
                    not _keys(response, SOURCE_FIELDS)
                    or type(response["sse"]) is not bytes
                    or not 0 < len(response["sse"]) <= MAX_SSE
                    or response["call_id"] != call["call_id"]
                    or response["request_sha256"] != call["request_sha256"]
                    or response["scope_sha256"] != call["scope_sha256"]
                    or not _digest(response["physical_manifest_sha256"])
                ):
                    raise ControlRefused("invalid_dispatch_receipt")
                receipt = self.collector.settle(
                    copy.deepcopy(attempt), copy.deepcopy(call), copy.deepcopy(response)
                )
                fields = SETTLEMENT_FIELDS
                if self.rated:
                    fields = fields - {"billed_microusd"} | {
                        "usage_rated_microusd",
                        "usage_rated_usd",
                        "tariff_sha256",
                        "audit_sha256",
                    }
                if (
                    not _keys(receipt, fields)
                    or any(
                        receipt[k] != call[k]
                        for k in ("call_id", "request_sha256", "scope_sha256")
                    )
                    or receipt["route_sha256"] != self.config["route_sha256"]
                    or receipt["physical_manifest_sha256"]
                    != response["physical_manifest_sha256"]
                    or not _digest(receipt["billing_receipt_sha256"])
                    or not _integer(receipt[self.cost_key], 0, 750000)
                    or self.rated
                    and (
                        receipt["tariff_sha256"] != self.config["tariff_sha256"]
                        or not _digest(receipt["audit_sha256"])
                        or _micros(_rated_usd(receipt["usage_rated_usd"]))
                        != receipt["usage_rated_microusd"]
                    )
                    or receipt["source"]
                    != (
                        "synthetic"
                        if self.config["mode"] == "rehearsal"
                        else (
                            "audited_usage_rated" if self.rated else "provider_billed"
                        )
                    )
                    or receipt["all_calls_complete"] is not True
                    or sum(r[self.cost_key] for r in state["receipts"])
                    + receipt[self.cost_key]
                    > 750000
                ):
                    raise ControlRefused("invalid_billing_receipt")
                state["receipts"].append(copy.deepcopy(receipt))
                state["next"] += 1
                state["phase"] = "ready"
                return {
                    "sse": response["sse"],
                    "call_id": call["call_id"],
                    "physical_manifest_sha256": response["physical_manifest_sha256"],
                    "billing_receipt_sha256": receipt["billing_receipt_sha256"],
                    self.cost_key: receipt[self.cost_key],
                } | (
                    {
                        "cost_basis": "audited_usage_rated",
                        "tariff_sha256": receipt["tariff_sha256"],
                        "audit_sha256": receipt["audit_sha256"],
                    }
                    if self.rated
                    else {}
                )
            except ControlRefused:
                raise
            except Exception:
                raise ControlRefused("dispatch_outcome_unknown") from None

    def revoke(self, attempt):
        with self.lock:
            self._validate_attempt(attempt)
            state = self.states.get(attempt["attempt_id"])
            if state is None or state["attempt"] != attempt:
                raise ControlRefused("attempt_unavailable")
            try:
                self.launch.close(
                    copy.deepcopy(attempt), state["grant"]["scope_sha256"]
                )
            except Exception:
                raise ControlRefused("revocation_outcome_unknown") from None
            state["closed"] = True

    def billing(self, attempt, generation):
        with self.lock:
            state = self._state(attempt, allow_closed=True)
            receipts = state["receipts"]
            manifest = [
                {
                    k: receipt[k]
                    for k in (
                        "call_id",
                        "physical_manifest_sha256",
                        "billing_receipt_sha256",
                        "request_sha256",
                    )
                }
                for receipt in receipts
            ]
            if (
                type(generation) is not dict
                or generation.get("attempt_id") != attempt["attempt_id"]
                or generation.get("dispatch_manifest_sha256")
                != binding_digest(manifest)
                or not receipts
                or generation.get("call_ids") != [r["call_id"] for r in receipts]
            ):
                raise ControlRefused("incomplete_attempt_billing")
            return {
                "attempt_id": attempt["attempt_id"],
                "dispatch_manifest_sha256": generation["dispatch_manifest_sha256"],
                "call_ids": [r["call_id"] for r in receipts],
                self.cost_key: _micros(
                    sum(
                        (_rated_usd(r["usage_rated_usd"]) for r in receipts), Decimal(0)
                    )
                )
                if self.rated
                else sum(r["billed_microusd"] for r in receipts),
                "receipt_sha256": binding_digest(receipts),
                "source": "synthetic"
                if self.config["mode"] == "rehearsal"
                else ("audited_usage_rated" if self.rated else "provider_billed"),
                "all_calls_complete": True,
            } | (
                {
                    "tariff_sha256": self.config["tariff_sha256"],
                    "audit_sha256": binding_digest(
                        {
                            "tariff_sha256": self.config["tariff_sha256"],
                            "receipts": receipts,
                        }
                    ),
                }
                if self.rated
                else {}
            )

    def reconcile(self, attempt, persisted_record):
        self._validate_attempt(attempt)
        return {
            "attempt_id": attempt["attempt_id"],
            "status": "unknown",
            "admission": None,
            "generation": None,
            "evaluation": None,
            "billing": None,
            "reconciliation_receipt_sha256": binding_digest(
                {"attempt": attempt["attempt_id"], "status": "unknown"}
            ),
        }
