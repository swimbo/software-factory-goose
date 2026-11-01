#!/usr/bin/env python3
"""Disposable real-wallet/custody replay; no production or provider authority.

Run as Root inside a bounded network-none controller with an EXT-family fresh
Python rootfs containing /opt/runtime (current harness_runtime_fixture built
with registry-sidecar) and /opt/restate-server (pinned 1.8.0). Bind /dev/null and
/dev/urandom into that rootfs. The controller needs CHOWN, DAC_OVERRIDE, KILL,
SETUID, SETGID and SYS_CHROOT only. No production paths are mounted.

The --rootfs directory must contain only the prepared public runtime assets and
an exact SFACTORY_WALLET_CUSTODY_DISPOSABLE marker. Sources are copied from this
checkout; the fixture never installs or executes against production. Root
allowances, route bounds and physical usage are explicitly synthetic. Actual
Rust durable journal methods, protected Python transports, SQLite transactions
and kernel peer UIDs are exercised; actual Bifrost/provider capture is not.
"""

import argparse
import copy
from dataclasses import replace
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import sqlite3
import struct
import subprocess
import sys
import time

OWNER = "wallet-custody-fixture"
PREFIX = "/var/lib/sfactory-harness"
WALLET = PREFIX + "/wallet/socket/service.sock"
BACKEND = PREFIX + "/wallet/backend/journal.sock"
GATEWAY = PREFIX + "/broker/socket/service.sock"
CAPTURE = PREFIX + "/capture/socket/service.sock"
DATABASE = PREFIX + "/capture/state/capture.db"
MARKER = "SFACTORY_WALLET_CUSTODY_DISPOSABLE"
GROUP = 3003
METHODS = {
    "initialize", "admit_attempt", "admit_day", "revoke", "reserve", "begin",
    "claim_receipts", "complete",
}
LIMIT = 65536


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class HTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(10)
        self.sock.connect(self.path)


def post(path, method, body, prefix="/spending/"):
    connection = HTTP(path)
    try:
        connection.request("POST", prefix + method, canonical(body),
                           {"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(LIMIT + 1)
        require(len(raw) <= LIMIT, "fixture response overflow")
        return response.status, json.loads(raw) if raw and response.status == 200 else None
    finally:
        connection.close()


def tcp_post(port, path, body):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request("POST", path, canonical(body),
                           {"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(LIMIT + 1)
        require(len(raw) <= LIMIT, "fixture response overflow")
        return response.status, json.loads(raw) if raw and response.status == 200 else None
    finally:
        connection.close()


def drop(uid):
    os.setgroups([] if uid == 2001 else [GROUP])
    os.setgid(uid)
    os.setuid(uid)


def fork_service(uid, name, run):
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read)
            log = os.open("/logs/" + name + ".log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.dup2(log, 1)
            os.dup2(log, 2)
            os.close(log)
            drop(uid)
            run(write)
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
    os.close(write)
    import select
    ready, _, _ = select.select([read], [], [], 15)
    okay = ready and os.read(read, 1) == b"1"
    os.close(read)
    if not okay:
        stop_pid(pid)
        raise RuntimeError("fixture service startup failed: " + name)
    return pid


def actor(uid, fn):
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read)
            drop(uid)
            output = canonical(fn()).encode()
            require(len(output) < LIMIT, "actor output overflow")
            os.write(write, output)
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
    os.close(write)
    import select
    ready, _, _ = select.select([read], [], [], 20)
    raw = os.read(read, LIMIT) if ready else b""
    os.close(read)
    if not ready:
        stop_pid(pid)
        raise RuntimeError("fixture actor timeout")
    require(os.waitpid(pid, 0)[1] == 0, "fixture actor failed")
    return json.loads(raw)


def stop_pid(pid):
    found, _ = os.waitpid(pid, os.WNOHANG)
    if not found:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


def stop_process(process):
    if process is not None and process.poll() is None:
        process.kill()
        process.wait(timeout=10)


def wait_socket(path, process):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        require(process.poll() is None, "owned fixture process exited")
        if Path(path).is_socket():
            return
        time.sleep(0.05)
    raise RuntimeError("fixture socket startup timeout")


def remove_socket(path):
    target = Path(path)
    if target.exists():
        require(target.is_socket(), "refusing non-socket cleanup")
        target.unlink()


def start_binary(args, name, gid=2004):
    def identity():
        os.setgroups([GROUP])
        os.setgid(gid)
        os.setuid(2004)
    log = open("/logs/" + name + ".log", "ab", buffering=0)
    try:
        return subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, close_fds=True,
                                cwd=PREFIX + "/wallet/state", preexec_fn=identity,
                                env={"PATH": "/usr/local/bin:/usr/bin:/bin",
                                     "TOKIO_WORKER_THREADS": "2", "RUST_LOG": "info"})
    finally:
        log.close()


def start_journal():
    log = Path("/logs/restate.log")
    log.write_text("")
    process = start_binary([
        "/opt/restate-server", "--base-dir", PREFIX + "/wallet/state/restate",
        "--node-name", "wallet-custody-fixture", "--bind-ip", "127.0.0.1",
        "--use-random-ports", "true", "--listen-mode", "tcp", "--no-logo",
        "--log-format", "json",
    ], "restate")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        require(process.poll() is None, "owned fixture Restate exited")
        ports = {}
        for line in log.read_text().splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if "listening" in item.get("fields", {}).get("message", "").lower():
                span = item.get("span", {})
                ports[span.get("server_name")] = span.get("server.port")
        if ports.get("admin-api-server") and ports.get("http-ingress-server"):
            return process, ports
        time.sleep(0.1)
    stop_process(process)
    raise RuntimeError("owned fixture Restate startup timeout")


def start_backend(port):
    remove_socket(BACKEND)
    def run(write):
        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            address_family = socket.AF_UNIX
            daemon_threads = True
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                uid = struct.unpack("3i", self.connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
                method = self.path.rsplit("/", 1)[-1]
                if uid != 2004 or method not in METHODS or self.path != (
                        "/restate/call/HarnessSpending/" + OWNER + "/" + method):
                    self.send_error(403)
                    return
                lengths = self.headers.get_all("Content-Length", [])
                if (len(lengths) != 1 or not lengths[0].isdecimal()
                        or not 0 < int(lengths[0]) <= 1048576):
                    self.send_error(400)
                    return
                body = self.rfile.read(int(lengths[0]))
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    connection.request("POST", self.path, body,
                                       {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    raw = response.read(LIMIT + 1)
                    require(len(raw) <= LIMIT, "backend output overflow")
                    self.send_response(response.status)
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(raw)
                finally:
                    connection.close()
        server = Server(BACKEND, Handler)
        os.chmod(BACKEND, 0o600)
        os.write(write, b"1")
        os.close(write)
        server.serve_forever()
    return fork_service(2004, "backend", run)


def start_frontend():
    remove_socket(WALLET)
    process = start_binary([
        "/opt/runtime", "ingress", WALLET, BACKEND, "2004", "2005", "2006",
        "2001", OWNER,
    ], "frontend", gid=GROUP)
    wait_socket(WALLET, process)
    return process


def make_data():
    from test_physical_usage import fixture
    from usage_rating import TariffCard, TariffRate
    binding, profile, envelope = fixture()
    card = TariffCard("1", "constant_peak", "https://example.org/pricing",
                      "b" * 64, 1, 1, 100000,
                      (TariffRate("provider", "model", "0.0000001", "0.0000001",
                                  "0.0000001", "0.0000002", "0"),))
    return binding, profile, envelope, card


def open_capture(profile, card, route):
    def run(write):
        from gateway_custody import ProtectedCaptureStore, PrivateCustodyServer
        store = ProtectedCaptureStore(
            DATABASE, service_uid=2008, owner=OWNER, route_sha256=route,
            tariff=card, profiles=(profile,), components=("answer", "fallback"),
            broker_uid=2005, gateway_uid=2007, collector_uid=2006,
        )
        server = PrivateCustodyServer(CAPTURE, store, service_uid=2008,
                                     socket_gid=GROUP, prefix="/capture/")
        os.write(write, b"1")
        os.close(write)
        server.serve_forever(poll_interval=0.1)
    return fork_service(2008, "capture", run)


def open_gateway(records, *, reserve):
    def run(write):
        from gateway_custody import (ProtectedGatewayAcquisitionAuthority,
                                    PrivateCaptureOpenClient, PrivateCustodyServer)
        from protected_spending_control import PrivateSpendingClient
        journal = PrivateSpendingClient(WALLET, service_uid=2004, broker_uid=2005,
                                        owner=OWNER)
        capture = PrivateCaptureOpenClient(CAPTURE, service_uid=2008,
                                           broker_uid=2005, owner=OWNER)
        authority = ProtectedGatewayAcquisitionAuthority(journal, capture,
                                                        gateway_uid=2007)
        for record in records:
            if reserve:
                require(journal("reserve", record["call"]) == "Reserved",
                        "fixture reservation failed")
            authority.arm(record["root"], record["call"])
        server = PrivateCustodyServer(GATEWAY, authority, service_uid=2005,
                                     socket_gid=GROUP, prefix="/gateway/")
        os.write(write, b"1")
        os.close(write)
        server.serve_forever(poll_interval=0.1)
    return fork_service(2005, "gateway", run)


def collector(record, profile, card):
    from physical_usage import (PrivateCaptureClient, PrivateCollectorClient,
                                PhysicalUsageCollector)
    source = PrivateCaptureClient(CAPTURE, service_uid=2008, collector_uid=2006,
                                  broker_uid=2005, worker_uid=2001, owner=OWNER)
    authority = PrivateCollectorClient(WALLET, service_uid=2004, collector_uid=2006,
                                       broker_uid=2005, worker_uid=2001, owner=OWNER)
    settled = PhysicalUsageCollector(source, authority, card, card.sha256(),
                                     (profile,), ("answer", "fallback"))
    attempt = {"attempt_id": record["root"]["attempt_id"], "budget_owner": OWNER,
               "route": record["root"]["route_sha256"], "mode": "live",
               "cost_basis": "audited_usage_rated", "tariff_sha256": card.sha256()}
    response = {k: record["call"][k] for k in
                ("call_id", "scope_sha256", "request_sha256")}
    response["physical_manifest_sha256"] = record["binding"].physical_manifest_sha256
    return settled.settle(attempt, record["call"], response)


def observed_open(root):
    from physical_usage import payload_sha256
    with sqlite3.connect(DATABASE, timeout=1) as connection:
        row = connection.execute("SELECT binding FROM roots WHERE id=?",
                                 (payload_sha256(root),)).fetchone()
    return row is not None and json.loads(row[0]) == root


def inside():
    require(os.geteuid() == 0 and Path("/" + MARKER).read_text() == MARKER + "\n",
            "disposable Root marker required")
    sys.path.insert(0, "/code")
    for path, uid, gid, mode in [
        ("/logs", 0, 0, 0o700), ("/var/lib", 0, 0, 0o755),
        (PREFIX, 0, 0, 0o755), (PREFIX + "/wallet", 0, 0, 0o755),
        (PREFIX + "/wallet/state", 2004, 2004, 0o700),
        (str(Path(BACKEND).parent), 2004, 2004, 0o700),
        (str(Path(WALLET).parent), 2004, GROUP, 0o750),
        (PREFIX + "/broker", 0, 0, 0o755),
        (str(Path(GATEWAY).parent), 2005, GROUP, 0o750),
        (PREFIX + "/capture", 0, 0, 0o755),
        (str(Path(CAPTURE).parent), 2008, GROUP, 0o750),
        (str(Path(DATABASE).parent), 2008, 2008, 0o700),
    ]:
        target = Path(path)
        target.mkdir(exist_ok=True)
        os.chmod(target, mode)
        os.chown(target, uid, gid)
    sdk = restate = frontend = None
    backend = capture = gateway = None
    try:
        sdk = start_binary(["/opt/runtime", "sdk", "127.0.0.1:19080"], "sdk")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", 19080)) == 0:
                    break
            require(sdk.poll() is None, "owned SDK exited")
            time.sleep(0.05)
        else:
            raise RuntimeError("owned SDK startup timeout")
        restate, ports = start_journal()
        # Exactly one registration dispatch. Unknown registration never retries.
        require(tcp_post(ports["admin-api-server"], "/deployments",
                         {"uri": "http://127.0.0.1:19080", "force": False,
                          "breaking": False})[0] in (200, 201),
                "fixture registration unknown")
        backend = start_backend(ports["http-ingress-server"])
        frontend = start_frontend()
        now = time.time_ns() // 1000000
        bootstrap = {
            "owner": OWNER, "policy_sha256": "a" * 64,
            "predecessor_fence_sha256": "b" * 64, "inventory_sha256": "c" * 64,
            "observed_at_ms": now, "approved_daily_cap_microusd": 5000000,
            "daily_cap_microusd": 5000000,
            "opening_tasks": {"task0": 0, "task1": 0, "other": 0},
            "opening_days": {str(now // 86400000): 4800000}, "scopes": [],
        }
        require(post(WALLET, "initialize", bootstrap)[0] == 200,
                "fixture wallet bootstrap failed")
        base_binding, profile, base_envelope, card = make_data()
        route = base_binding.route_sha256
        records = []
        from gateway_custody import root_binding
        from physical_usage import payload_sha256
        def admit(task, attempt, amount):
            issued = time.time_ns() // 1000000
            scope = {"task": task, "attempt": attempt,
                     "generation": task + "-" + str(attempt), "worker": "worker",
                     "lease_sha256": "d" * 64, "issued_at_ms": issued,
                     "expires_at_ms": issued + 300000,
                     "route": {"route_sha256": route, "review_sha256": "f" * 64,
                               "usage_tariff_sha256": card.sha256(),
                               "valid_from_ms": issued, "valid_until_ms": issued + 300000,
                               "max_request_bytes": 65536, "max_output_tokens": 100,
                               "components": [{"id": "answer", "max_charge_microusd": amount - 1},
                                              {"id": "fallback", "max_charge_microusd": 1}]}}
            code, digest = post(WALLET, "admit_attempt", scope)
            require(code == 200, "fixture attempt admission failed")
            return digest
        for index in range(2):
            scope = admit("task" + str(index), 1, 100000)
            call_id = "logical_" + str(index)
            binding = replace(base_binding, owner=OWNER, call_id=call_id,
                              scope_sha256=scope, tariff_sha256=card.sha256(),
                              attempt_id="run_" + str(index + 1) * 64)
            envelope = copy.deepcopy(base_envelope)
            envelope["snapshot"]["root_id"] = call_id
            digest = payload_sha256({k: envelope[k] for k in
                                     ("snapshot", "component_calls", "absent_components")})
            binding = replace(binding, physical_manifest_sha256=digest)
            envelope["binding"] = binding.as_dict()
            records.append({"root": root_binding(binding.as_dict()), "binding": binding,
                            "envelope": envelope,
                            "call": {"call_id": call_id, "scope_sha256": scope,
                                     "request_sha256": binding.request_sha256,
                                     "sequence": 0, "request_bytes": 1000,
                                     "output_tokens": 100}})
        capture = open_capture(profile, card, route)
        gateway = open_gateway(records, reserve=True)
        def worker_denial():
            denied = []
            for path in (WALLET, GATEWAY, CAPTURE):
                connection = socket.socket(socket.AF_UNIX)
                try:
                    connection.connect(path)
                except PermissionError:
                    denied.append(path)
                else:
                    raise RuntimeError("worker crossed custody filesystem boundary")
                finally:
                    connection.close()
            return denied
        require(actor(2001, worker_denial) == [WALLET, GATEWAY, CAPTURE],
                "worker was not denied before HTTP")
        require(actor(2006, lambda: post(WALLET, "reserve", records[0]["call"]))[0] == 403,
                "collector could reserve")
        require(actor(2007, lambda: post(WALLET, "begin", records[0]["call"]))[0] == 403,
                "gateway bypassed broker begin authority")
        def acquire(record):
            return post(GATEWAY, "acquire", {"binding": record["root"],
                                             "call": record["call"]}, "/gateway/")
        successful = actor(2007, lambda: acquire(records[0]))
        require(successful == [200, {"root_sha256": payload_sha256(records[0]["root"]),
                                     "acquired": True}], "real wallet acquisition failed")
        require(actor(2007, lambda: acquire(records[0]))[0] == 400,
                "gateway replay acquired again")
        def direct_begin(record):
            return post(WALLET, "begin", record["call"])
        require(actor(2005, lambda: direct_begin(records[0]))[0] == 409,
                "wallet began acquired root twice")
        def drop_ack():
            body = canonical({"binding": records[1]["root"], "call": records[1]["call"]}).encode()
            connection = socket.socket(socket.AF_UNIX)
            try:
                connection.connect(GATEWAY)
                connection.sendall(b"POST /gateway/acquire HTTP/1.1\r\nHost: localhost\r\n"
                                   b"Content-Type: application/json\r\nContent-Length: " +
                                   str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                connection.shutdown(socket.SHUT_RDWR)
            finally:
                connection.close()
            return {"reply_read": False}
        require(actor(2007, drop_ack) == {"reply_read": False}, "ack-drop fixture failed")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not observed_open(records[1]["root"]):
            time.sleep(0.05)
        require(observed_open(records[1]["root"]), "lost acknowledgement did not commit capture open")
        require(actor(2007, lambda: acquire(records[1]))[0] == 400,
                "lost acknowledgement rearmed gateway")
        require(actor(2005, lambda: direct_begin(records[1]))[0] == 409,
                "lost acknowledgement rearmed durable wallet")
        require(actor(2007, lambda: post(CAPTURE, "close", records[0]["envelope"],
                                       "/capture/"))[0] == 200, "complete closure failed")
        settlement = actor(2006, lambda: collector(records[0], profile, card))
        require(settlement["usage_rated_microusd"] == 2 and settlement["all_calls_complete"] is True,
                "real collector settlement failed")
        # The two reservations consume exactly the remaining UTC-day authority.
        other_scope = admit("other", 1, 2)
        other_call = records[0]["call"] | {"call_id": "other", "scope_sha256": other_scope}
        require(actor(2005, lambda: post(WALLET, "reserve", other_call)) == [200, "Denied"],
                "settlement refunded day authority")
        # Restart actual durable Restate plus transports; do not reuse stale sockets.
        stop_pid(gateway)
        gateway = None
        stop_pid(capture)
        capture = None
        stop_process(frontend)
        frontend = None
        stop_pid(backend)
        backend = None
        stop_process(restate)
        restate = None
        remove_socket(GATEWAY)
        remove_socket(CAPTURE)
        restate, ports = start_journal()
        backend = start_backend(ports["http-ingress-server"])
        frontend = start_frontend()
        capture = open_capture(profile, card, route)
        gateway = open_gateway(records, reserve=False)
        for record in records:
            require(actor(2007, lambda r=record: acquire(r))[0] == 400,
                    "restart created a new begin authority")
            require(actor(2005, lambda r=record: direct_begin(r))[0] == 409,
                    "durable begin outcome lost at restart")
        require(actor(2006, lambda: collector(records[0], profile, card)) == settlement,
                "settled capture/audit changed after restart")
        require(actor(2005, lambda: post(WALLET, "reserve", other_call)) == [200, "Denied"],
                "day cap changed after restart")
        require(post(WALLET, "initialize", bootstrap | {"opening_days": {str(now // 86400000): 0}})[0] == 409,
                "restart accepted reset opening inventory")
        result = {
            "schema": 1, "component": "real_wallet_and_private_custody_join",
            "real_durable_wallet": True, "real_kernel_uids": True,
            "real_capture_sqlite": True,
            "worker_denied_before_http": True,
            "gateway_and_collector_money_roles_denied": True, "real_collector_wallet_settlement": True,
            "successful_acquisition": successful[1],
            "lost_acquisition_ack_not_rearmed": True,
            "journal_capture_and_broker_restart_preserved_outcomes": True,
            "day_cap_denied_after_low_cost_settlement_and_restart": True,
            "opening_inventory_reset_denied": True,
            "settled_usage_rated_microusd": settlement["usage_rated_microusd"],
            "roles": {"root": 0, "wallet": 2004, "broker": 2005,
                      "gateway": 2007, "capture": 2008, "collector": 2006,
                      "worker": 2001},
            "caps_microusd": {"utc_day": 5000000, "permanent_task": 750000},
            "synthetic_root_bootstrap_and_charge_bounds": True,
            "synthetic_physical_usage": True, "actual_bifrost_capture": False,
            "production_admission": False, "paid_calls": 0, "live_attempts": 0,
            "candidate_enabled": False,
            "source_sha256": {name: hashlib.sha256(Path("/code/" + name).read_bytes()).hexdigest()
                              for name in ("gateway_custody.py", "protected_spending_control.py",
                                           "physical_usage.py", "usage_rating.py", "usage_spending.py")},
            "binary_sha256": {name: hashlib.sha256(Path("/opt/" + name).read_bytes()).hexdigest()
                              for name in ("runtime", "restate-server")},
        }
        print(canonical(result), flush=True)
    finally:
        for pid in (gateway, capture, backend):
            if pid is not None:
                stop_pid(pid)
        for process in (frontend, restate, sdk):
            stop_process(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    args = parser.parse_args()
    root = args.rootfs
    require(os.geteuid() == 0 and root.is_absolute() and root.is_dir()
            and not root.is_symlink(), "fresh absolute disposable rootfs required")
    require((root / MARKER).read_text() == MARKER + "\n", "disposable marker required")
    require(not (root / "code").exists() and not (root / "logs").exists()
            and not (root / PREFIX.lstrip("/")).exists(), "fixture already attempted")
    require((root / "opt/runtime").is_file() and (root / "opt/restate-server").is_file(),
            "public native runtime assets required")
    source = Path(__file__).resolve().parents[2] / "crates/execution/harness"
    shutil.copytree(source, root / "code", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(__file__, root / "opt/wallet-custody-replay.py")
    os.chroot(root)
    os.chdir("/")
    os.execv("/usr/local/bin/python3", ["python3", "/opt/wallet-custody-replay.py", "--inside"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--inside"]:
        inside()
    else:
        main()
