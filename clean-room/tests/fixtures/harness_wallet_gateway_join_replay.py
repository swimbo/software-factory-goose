#!/usr/bin/env python3
"""Join real wallet, Root scope RPC, broker, capture and Bifrost in isolation.

The caller must use a fresh ext4-backed rootfs inside a network-none container,
bind only /dev/null, /dev/urandom and /proc/sys/kernel/random/boot_id read-only,
and supply the public pinned binaries /opt/runtime, /opt/restate-server and
/opt/wallet-gateway-test. No production paths, credentials or evaluator are
mounted. The exact marker is SFACTORY_WALLET_GATEWAY_DISPOSABLE. Registry gate,
catalog, lease, route, tariff, charge bounds and provider are synthetic. This is
not Root constructor, production bootstrap, admission, or budget qualification.
"""

import argparse
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness_wallet_custody_replay as base

MARKER = "SFACTORY_WALLET_GATEWAY_DISPOSABLE"
ROOT_SOCKET = base.PREFIX + "/root/socket/service.sock"
EXCHANGE = base.PREFIX + "/exchange/socket/service.sock"
TASK = "01K00000000000000000000001"
GENERATION = "01K00000000000000000000000"
DAY_FILL_TASK = "01K00000000000000000000002"
DAY_OVERFLOW_TASK = "01K00000000000000000000003"
ATTEMPT = "run_" + "1" * 64
ROUTE = "e" * 64
REVIEW = "f" * 64


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def setup_dirs():
    for path, uid, gid, mode in [
        ("/logs", 0, 0, 0o700), ("/var/lib", 0, 0, 0o755),
        (base.PREFIX, 0, 0, 0o755), (base.PREFIX + "/wallet", 0, 0, 0o755),
        (base.PREFIX + "/wallet/state", 2004, 2004, 0o700),
        (str(Path(base.BACKEND).parent), 2004, 2004, 0o700),
        (str(Path(base.WALLET).parent), 2004, base.GROUP, 0o750),
        (base.PREFIX + "/broker", 0, 0, 0o755),
        (str(Path(base.GATEWAY).parent), 2005, base.GROUP, 0o750),
        (base.PREFIX + "/capture", 0, 0, 0o755),
        (str(Path(base.CAPTURE).parent), 2008, base.GROUP, 0o750),
        (str(Path(base.DATABASE).parent), 2008, 2008, 0o700),
        (base.PREFIX + "/collector", 0, 0, 0o755),
        (str(Path(base.SETTLEMENT).parent), 2006, base.GROUP, 0o750),
        (base.PREFIX + "/exchange", 0, 0, 0o755),
        (str(Path(EXCHANGE).parent), 2007, base.GROUP, 0o750),
        (base.PREFIX + "/root", 0, 0, 0o755),
        (str(Path(ROOT_SOCKET).parent), 0, 2005, 0o750),
        (base.PREFIX + "/root/state", 0, 0, 0o700),
        (base.PREFIX + "/root/catalog", 0, 0, 0o700),
        ("/fixture", 0, 0, 0o755),
    ]:
        target = Path(path)
        target.mkdir(exist_ok=True)
        os.chmod(target, mode)
        os.chown(target, uid, gid)


def root_backend(scope, scope_hash, attempt, admission, deadline):
    import linux_supervisor as root
    from linux_runner import recipe

    launch_recipe = recipe(
        suite_sha256="b" * 64, config_sha256="c" * 64,
        profiles={"baseline": "d" * 64, "candidate": "a" * 64},
        script_host_sha256="1" * 64, normalizer_sha256="2" * 64,
        broker_uid=2005, worker_uid=2001,
    )
    now = time.time_ns() // 1_000_000
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    catalog = Path(base.PREFIX + "/root/catalog")
    state = Path(base.PREFIX + "/root/state")
    case = state / ATTEMPT
    case.mkdir(mode=0o700)
    attempt_hash = root.sha(attempt)
    control = {
        "status": "allowed", "attempt_id": ATTEMPT, "attempt_sha256": attempt_hash,
        "scope_sha256": scope_hash, "policy_sha256": "6" * 64,
        "owner": base.OWNER, "route_sha256": ROUTE, "expires_at_ms": deadline,
        "authority_receipt_sha256": admission["authority_receipt_sha256"],
        "cost_basis": "audited_usage_rated", "tariff_sha256": attempt["tariff_sha256"],
    }
    entry = {
        "schema": 1, "attempt": attempt, "admission_sha256": root.sha(admission),
        "recipe_sha256": root.sha(launch_recipe), "scope": scope,
        "scope_sha256": scope_hash, "factory_task_id": TASK, "control_grant": control,
        "cgroup": {"path": "/sys/fs/cgroup/sfactoryharness" + ATTEMPT[4:] + ".slice",
                   "dev": 1, "ino": 1, "boot_id": boot},
    }
    lease = {"schema": 1, "attempt_sha256": attempt_hash, "boot_id": boot,
             **{key: scope[key] for key in ("task", "generation", "worker", "lease_sha256", "issued_at_ms")},
             "expires_at_ms": deadline}
    # This public grant is a fixture preimage, not a production launch grant.
    grant = {"attempt_id": ATTEMPT, "expires_at_ms": deadline + 5_000}
    root.store(catalog / (ATTEMPT + ".json"), entry)
    root.store(catalog / (ATTEMPT + ".lease.json"), lease)
    root.store(case / "grant.json", grant)
    root.store(case / "prepare-intent.json", {"attempt": attempt, "admission": admission})
    root.store(case / "owner-scope.json", {"grant_sha256": root.sha(grant), "scope_sha256": scope_hash})
    backend = object.__new__(root.RootSupervisor)
    backend.state, backend.catalog = state, catalog
    backend.recipe = launch_recipe
    backend.slots = {ATTEMPT: {"attempt_sha256": attempt_hash, "task_id": attempt["task_id"],
                               "repeat": attempt["repeat"], "variant": attempt["variant"],
                               "factory_task_id": TASK}}
    backend.cfg = {"socket_path": ROOT_SOCKET}
    backend.guard = threading.Lock()
    backend.gate = SimpleNamespace(admission=contextlib.nullcontext)
    base.require(now < deadline, "fixture deadline expired")
    return backend


def start_root(backend):
    import select
    import linux_supervisor as root

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_fd)
            with root.Server(backend) as server:
                os.write(write_fd, b"1")
                os.close(write_fd)
                server.serve_forever(poll_interval=0.1)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    os.close(write_fd)
    ready, _, _ = select.select([read_fd], [], [], 10)
    okay = ready and os.read(read_fd, 1) == b"1"
    os.close(read_fd)
    if not okay:
        base.stop_pid(pid)
        raise RuntimeError("fixture Root server failed")
    return pid


def open_broker(attempt, grant, call, request, card, binding):
    def run(write):
        from gateway_custody import (PrivateCaptureOpenClient, PrivateCustodyServer,
                                     ProtectedGatewayAcquisitionAuthority)
        from gateway_transport import PrivateGatewayClient, ProtectedGatewayTransport
        from linux_runner import LinuxRunnerRefused, PrivateRootSupervisorClient
        from physical_settlement import PrivateSettlementClient
        from protected_spending_control import PrivateSpendingClient

        journal = PrivateSpendingClient(base.WALLET, service_uid=2004,
                                        broker_uid=2005, owner=base.OWNER)
        capture = PrivateCaptureOpenClient(base.CAPTURE, service_uid=2008,
                                           broker_uid=2005, owner=base.OWNER)
        authority = ProtectedGatewayAcquisitionAuthority(journal, capture, gateway_uid=2007)
        server = PrivateCustodyServer(base.GATEWAY, authority, service_uid=2005,
                                      socket_gid=base.GROUP, prefix="/gateway/")
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.1}, daemon=True)
        thread.start()
        os.write(write, b"1")
        os.close(write)
        deadline = time.monotonic() + 15
        while not Path(EXCHANGE).is_socket() or not Path(EXCHANGE).with_name("ready").is_file():
            base.require(time.monotonic() < deadline, "gateway fixture did not start")
            time.sleep(0.05)
        root_client = PrivateRootSupervisorClient(ROOT_SOCKET, broker_uid=2005)
        try:
            root_client("scope_preimage_v2", {"attempt": attempt, "scope_sha256": "0" * 64})
        except LinuxRunnerRefused:
            pass
        else:
            raise RuntimeError("Root accepted an altered scope digest")
        observed = root_client("scope_preimage_v2", {"attempt": attempt, "scope_sha256": call["scope_sha256"]})
        base.require(observed["root_deadline_ms"] == grant["expires_at_ms"] - 5_000,
                     "Root lease deadline mismatch")
        client = PrivateGatewayClient(EXCHANGE, gateway_uid=2007, broker_uid=2005, owner=base.OWNER)
        transport = ProtectedGatewayTransport(journal, authority, client, route_sha256=ROUTE,
                                              tariff_sha256=card.sha256(), mode="rehearsal",
                                              scope_client=root_client)
        base.require(journal("reserve", call) == "Reserved", "wallet reservation denied")
        response = transport.exchange_reserved(attempt, grant, call, request)
        base.require(b"public result" in response["sse"], "synthetic Bifrost output missing")
        from physical_usage import payload_sha256
        verified_calls = authority.roots[payload_sha256(binding)][6]
        base.require(verified_calls == 1, "physical wallet and Root verification missing")
        settlement = PrivateSettlementClient(base.SETTLEMENT, collector_uid=2006, broker_uid=2005,
                                             worker_uid=2001, owner=base.OWNER,
                                             route_sha256=ROUTE, tariff_sha256=card.sha256(), mode="rehearsal")
        receipt = settlement.settle(attempt, call, response)
        base.require(receipt["all_calls_complete"] is True and receipt["usage_rated_microusd"] == 1,
                     "captured usage did not settle")
        server.shutdown()
        thread.join(timeout=3)
        base.require(not thread.is_alive(), "broker server did not join")
        server.server_close()
        (Path(base.GATEWAY).parent / "result.json").write_text(base.canonical({
            "response": {key: value for key, value in response.items() if key != "sse"},
            "settlement": receipt, "root_deadline_ms": observed["root_deadline_ms"],
            "verified_physical_calls": verified_calls,
        }))
    return base.fork_service(2005, "broker", run)


def launch_gateway():
    def identity():
        os.setgroups([base.GROUP])
        os.setgid(2007)
        os.setuid(2007)
    log = open("/logs/bifrost-gateway.log", "ab", buffering=0)
    try:
        return subprocess.Popen(
            ["/opt/wallet-gateway-test", "-test.run=^TestFactoryWalletJoinedGateway$", "-test.v"],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            close_fds=True, preexec_fn=identity,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "SFACTORY_WALLET_JOIN_FIXTURE": "1"},
        )
    finally:
        log.close()


def inside():
    base.require(os.geteuid() == 0 and Path("/" + MARKER).read_text() == MARKER + "\n",
                 "disposable Root marker required")
    sys.path.insert(0, "/code")
    setup_dirs()
    from factory_harness import canonical
    from gateway_custody import root_binding
    from linux_supervisor import factory_scope_digest
    from physical_usage import UsageSchemaProfile
    from protected_spending_control import binding_digest
    from usage_rating import TariffCard, TariffRate

    card = TariffCard("1", "constant_peak", "https://example.org/pricing", "b" * 64,
                      1, 1, 2**63 - 1,
                      (TariffRate("openai", "gpt-4o", "0.0000001", "0.0000001",
                                  "0.0000001", "0.0000002", "0"),))
    profile = UsageSchemaProfile("chat-v1", "openai", "gpt-4o", ("answer",), "a" * 64,
                                 "usage.prompt_tokens", "usage.completion_tokens",
                                 "inclusive_output_total", None, None, None)
    processes = {"sdk": None, "restate": None, "frontend": None, "gateway": None}
    children = {"backend": None, "root": None, "capture": None, "settler": None, "broker": None}
    try:
        processes["sdk"] = base.start_binary(["/opt/runtime", "sdk", "127.0.0.1:19080"], "sdk")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", 19080)) == 0:
                    break
            base.require(processes["sdk"].poll() is None, "fixture SDK exited")
            time.sleep(0.05)
        else:
            raise RuntimeError("fixture SDK startup timeout")
        processes["restate"], ports = base.start_journal()
        base.require(base.tcp_post(ports["admin-api-server"], "/deployments",
                    {"uri": "http://127.0.0.1:19080", "force": False, "breaking": False})[0] in (200, 201),
                     "fixture registration unknown")
        children["backend"] = base.start_backend(ports["http-ingress-server"])
        processes["frontend"] = base.start_frontend()
        now = time.time_ns() // 1_000_000
        scope_expiry = min(now + 120_000, (now // 86_400_000 + 1) * 86_400_000)
        lease_expiry = scope_expiry - 30_000
        base.require(lease_expiry - now >= 30_000, "fixture too close to UTC day boundary")
        bootstrap = {"owner": base.OWNER, "policy_sha256": "a" * 64,
                     "predecessor_fence_sha256": "b" * 64, "inventory_sha256": "c" * 64,
                     "observed_at_ms": now, "approved_daily_cap_microusd": 5_000_000,
                     "daily_cap_microusd": 5_000_000,
                     "opening_tasks": {TASK: 649_999, DAY_FILL_TASK: 0, DAY_OVERFLOW_TASK: 0},
                     "opening_days": {str(now // 86_400_000): 4_149_998}, "scopes": []}
        bootstrap_status = base.post(base.WALLET, "initialize", bootstrap)[0]
        base.require(bootstrap_status == 200, f"wallet initialize failed status={bootstrap_status}")
        scope = {"task": TASK, "attempt": 1, "generation": GENERATION, "worker": "worker",
                 "lease_sha256": "d" * 64, "issued_at_ms": now, "expires_at_ms": scope_expiry,
                 "route": {"route_sha256": ROUTE, "review_sha256": REVIEW,
                           "usage_tariff_sha256": card.sha256(), "valid_from_ms": now,
                           "valid_until_ms": scope_expiry, "max_request_bytes": 65536,
                           "max_output_tokens": 100,
                           "components": [{"id": "answer", "max_charge_microusd": 100_000},
                                          {"id": "fallback", "max_charge_microusd": 1}]}}
        code, scope_hash = base.post(base.WALLET, "admit_attempt", scope)
        base.require(code == 200 and scope_hash == factory_scope_digest(scope), "wallet scope differs")
        attempt = {"attempt_id": ATTEMPT, "task_id": "public-fixture", "variant": "baseline", "repeat": 0,
                   "budget_owner": base.OWNER, "route": ROUTE, "mode": "rehearsal",
                   "cost_basis": "audited_usage_rated", "tariff_sha256": card.sha256()}
        admission = {"attempt_id": ATTEMPT, "status": "allowed", "authority_receipt_sha256": "3" * 64}
        grant = {"attempt_id": ATTEMPT, "owner": base.OWNER, "route_sha256": ROUTE,
                 "tariff_sha256": card.sha256(), "scope_sha256": scope_hash,
                 "expires_at_ms": lease_expiry + 5_000}
        request = {"model": "auto", "messages": [{"role": "user", "content": "public"}], "tools": [],
                   "max_tokens": 16, "stream": True, "stream_options": {"include_usage": True}}
        call = {"call_id": "logical", "scope_sha256": scope_hash, "request_sha256": binding_digest(request),
                "sequence": 0, "request_bytes": len(canonical(request).encode()), "output_tokens": 16}
        binding = root_binding({"schema": 1, "owner": base.OWNER, "attempt_id": ATTEMPT,
                                "call_id": call["call_id"], "scope_sha256": scope_hash,
                                "route_sha256": ROUTE, "request_sha256": call["request_sha256"],
                                "tariff_sha256": card.sha256()})
        Path("/fixture/wallet-gateway.json").write_text(base.canonical({
            "binding": binding, "call": call, "expires_at_ms": grant["expires_at_ms"],
            "review_sha256": REVIEW,
        }))
        os.chmod("/fixture/wallet-gateway.json", 0o444)
        root = root_backend(scope, scope_hash, attempt, admission, lease_expiry)
        children["root"] = start_root(root)
        def worker_root_denied():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                try:
                    client.connect(ROOT_SOCKET)
                except PermissionError:
                    return True
                raise RuntimeError("worker crossed the Root socket boundary")
        base.require(base.actor(2001, worker_root_denied), "worker reached Root socket")
        children["capture"] = base.open_capture(profile, card, ROUTE)
        children["settler"] = base.open_settlement(profile, card, ROUTE, mode="rehearsal")
        children["broker"] = open_broker(attempt, grant, call, request, card, binding)
        processes["gateway"] = launch_gateway()
        result_path = Path(base.GATEWAY).parent / "result.json"
        deadline = time.monotonic() + 25
        while not result_path.is_file():
            base.require(time.monotonic() < deadline, "joined fixture timed out")
            if processes["gateway"].poll() is not None:
                base.require(processes["gateway"].returncode == 0, "Bifrost gateway failed")
            time.sleep(0.05)
        deadline = time.monotonic() + 5
        while True:
            pid, status = os.waitpid(children["broker"], os.WNOHANG)
            if pid:
                children["broker"] = None
                base.require(os.waitstatus_to_exitcode(status) == 0, "broker exited unsuccessfully")
                break
            base.require(time.monotonic() < deadline, "broker did not exit")
            time.sleep(0.05)
        result = json.loads(result_path.read_text())
        base.require(processes["gateway"].poll() is None, "listener stopped before broker settled")
        processes["gateway"].send_signal(signal.SIGTERM)
        base.require(processes["gateway"].wait(timeout=10) == 0, "Bifrost gateway exit failed")
        base.require(base.actor(2005, lambda: base.post(base.WALLET, "begin", call))[0] == 409,
                     "wallet allowed repeated begin")
        next_call = call | {"call_id": "task-over-cap", "sequence": 1}
        base.require(base.actor(2005, lambda: base.post(base.WALLET, "reserve", next_call)) == [200, "Denied"],
                     "permanent task cap did not deny with daily budget remaining")

        def admit_test_scope(task, amount):
            item = copy.deepcopy(scope)
            item["task"] = task
            item["route"]["components"] = [{"id": "answer", "max_charge_microusd": amount}]
            code, identity = base.post(base.WALLET, "admit_attempt", item)
            base.require(code == 200 and identity == factory_scope_digest(item), "test scope admission failed")
            return identity

        fill_scope = admit_test_scope(DAY_FILL_TASK, 750_000)
        fill_call = call | {"call_id": "daily-fill", "scope_sha256": fill_scope, "sequence": 0}
        base.require(base.actor(2005, lambda: base.post(base.WALLET, "reserve", fill_call)) == [200, "Reserved"],
                     "daily positive-control reservation failed")
        overflow_scope = admit_test_scope(DAY_OVERFLOW_TASK, 2)
        overflow_call = call | {"call_id": "daily-over-cap", "scope_sha256": overflow_scope, "sequence": 0}
        base.require(base.actor(2005, lambda: base.post(base.WALLET, "reserve", overflow_call)) == [200, "Denied"],
                     "daily cap did not deny a task below its own limit")
        base.require(base.observed_open(binding), "SQLite capture root missing")
        with sqlite3.connect(base.DATABASE, timeout=1) as db:
            rows = db.execute("SELECT binding, closure, audit FROM roots").fetchall()
        base.require(len(rows) == 1 and all(rows[0]), "capture closure or audit missing")
        stored_binding, closure, audit = (json.loads(value) for value in rows[0])
        calls = closure["snapshot"]["calls"]
        base.require(
            stored_binding == binding and closure["snapshot"]["sealed"] is True
            and closure["snapshot"]["complete"] is True and len(calls) == 1
            and closure["component_calls"] == {"answer": ["public"]}
            and set(closure["absent_components"]) == {"fallback"}
            and calls[0]["permit_id"] == "public" and calls[0]["state"] == "complete"
            and calls[0]["role"] == "answer" and calls[0]["provider"] == "openai"
            and calls[0]["model"] == "gpt-4o"
            and calls[0]["usage"].get("usage.prompt_tokens") == 1
            and calls[0]["usage"].get("usage.completion_tokens") == 1
            and audit["usage_rated_microusd"] == 1
            and audit["capture_sha256"] == result["response"]["physical_manifest_sha256"],
            "captured physical usage or audit differs",
        )
        base.require(result["root_deadline_ms"] == lease_expiry, "Root deadline lost")
        print(base.canonical({"schema": 1, "component": "wallet_root_broker_bifrost_capture_join", "mode": "rehearsal",
                              "wallet_actual": True, "root_scope_methods_actual": True,
                              "root_constructor_and_registry_synthetic": True,
                              "real_broker_and_capture": True, "actual_bifrost_handler": True,
                              "private_listener_joined_and_cancelled": True,
                              "inherited_listener_handoff": True,
                              "provider_authorizer_route_and_charge_bounds_synthetic": True,
                              "wallet_begin_replay_after_completion_denied": True,
                              "task_cap_denied_with_daily_headroom": True,
                              "daily_cap_denied_with_task_headroom": True,
                              "altered_root_scope_denied": True, "worker_root_socket_denied": True,
                              "settled_usage_rated_microusd": result["settlement"]["usage_rated_microusd"],
                              "root_lease_deadline_observed": True, "paid_calls": 0,
                              "physical_scope_and_wallet_checks": result["verified_physical_calls"],
                              "live_attempts": 0, "candidate_activation_performed": False,
                              "production_admission": False,
                              "binary_sha256": {name: digest("/opt/" + name) for name in
                                                ("runtime", "restate-server", "wallet-gateway-test")},
                              "fixture_sha256": {name: digest("/opt/" + name) for name in
                                                 ("wallet-gateway-join.py", "harness_wallet_custody_replay.py")},
                              "harness_sha256": {name: digest("/code/" + name) for name in
                                                 ("linux_supervisor.py", "linux_runner.py", "gateway_custody.py",
                                                  "gateway_transport.py", "protected_spending_control.py", "physical_usage.py",
                                                  "physical_settlement.py", "usage_rating.py", "factory_harness.py")}}), flush=True)
    finally:
        for name in ("broker", "settler", "capture", "root", "backend"):
            if children[name] is not None:
                base.stop_pid(children[name])
        for name in ("gateway", "frontend", "restate", "sdk"):
            base.stop_process(processes[name])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    root = parser.parse_args().rootfs
    base.require(os.geteuid() == 0 and root.is_absolute() and root.is_dir() and not root.is_symlink(),
                 "fresh absolute disposable rootfs required")
    base.require((root / MARKER).read_text() == MARKER + "\n", "disposable marker required")
    base.require(not (root / "code").exists() and not (root / "logs").exists()
                 and not (root / base.PREFIX.lstrip("/")).exists(), "fixture already attempted")
    base.require(all((root / "opt" / name).is_file() for name in
                     ("runtime", "restate-server", "wallet-gateway-test")), "fixture binaries missing")
    source = Path(__file__).resolve().parents[2] / "crates/execution/harness"
    shutil.copytree(source, root / "code", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(__file__, root / "opt/wallet-gateway-join.py")
    shutil.copyfile(Path(__file__).with_name("harness_wallet_custody_replay.py"),
                    root / "opt/harness_wallet_custody_replay.py")
    os.chroot(root)
    os.chdir("/")
    os.execv("/usr/local/bin/python3", ["python3", "/opt/wallet-gateway-join.py", "--inside"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--inside"]:
        inside()
    else:
        main()
