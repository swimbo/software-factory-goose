#!/usr/bin/env python3
"""Join real wallet, Root scope RPC, broker, capture and Bifrost in isolation.

The caller must use a fresh ext4-backed rootfs inside a network-none container,
bind only /dev/null, /dev/urandom and /proc/sys/kernel/random/boot_id read-only,
and supply the public pinned binaries /opt/runtime, /opt/restate-server and
/opt/wallet-gateway-test. No production paths, credentials or evaluator are
mounted. The exact marker is SFACTORY_WALLET_GATEWAY_DISPOSABLE. Registry gate,
lease, tariff, charge bounds and loopback provider are synthetic. Scoped catalog,
retained-route rules, governor, semantic warmup and inference runtime are actual. This is
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
COMPONENTS = ("embedding", "classifier", "classifier_responses", "answer", "fallback")
EXPECTED_PHYSICAL_CALLS = 8
IDENTITY_CASES = ("matching", "changed_credential", "missing_credential", "changed_user", "responses_executor", "classifier_rejected")


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


def open_capture(profiles, card, route, *, lost_ack_call=None):
    def run(write):
        from gateway_custody import ProtectedCaptureStore, PrivateCustodyServer
        store = ProtectedCaptureStore(
            base.DATABASE, service_uid=2008, owner=base.OWNER, route_sha256=route,
            tariff=card, profiles=profiles, components=COMPONENTS,
            broker_uid=2005, gateway_uid=2007, collector_uid=2006,
        )
        if lost_ack_call is not None:
            original_dispatch = store.dispatch

            def lost_ack(uid, method, body):
                result = original_dispatch(uid, method, body)
                if method == "close" and body["binding"]["call_id"] == lost_ack_call:
                    raise RuntimeError("public fixture loses acknowledged durable closure")
                return result

            store.dispatch = lost_ack
        server = PrivateCustodyServer(base.CAPTURE, store, service_uid=2008,
                                     socket_gid=base.GROUP, prefix="/capture/")
        os.write(write, b"1")
        os.close(write)
        server.serve_forever(poll_interval=0.1)
    return base.fork_service(2008, "capture", run)


def open_settlement(profiles, card, route):
    def run(write):
        from gateway_custody import PrivateCustodyServer
        from physical_settlement import ProtectedUsageSettlement
        from physical_usage import PrivateCaptureClient, PrivateCollectorClient, PhysicalUsageCollector
        source = PrivateCaptureClient(base.CAPTURE, service_uid=2008, collector_uid=2006,
                                      broker_uid=2005, worker_uid=2001, owner=base.OWNER)
        authority = PrivateCollectorClient(base.WALLET, service_uid=2004, collector_uid=2006,
                                           broker_uid=2005, worker_uid=2001, owner=base.OWNER)
        collector = PhysicalUsageCollector(source, authority, card, card.sha256(),
                                           profiles, COMPONENTS, mode="rehearsal")
        backend = ProtectedUsageSettlement(collector, broker_uid=2005, worker_uid=2001,
                                            route_sha256=route)
        server = PrivateCustodyServer(base.SETTLEMENT, backend, service_uid=2006,
                                      socket_gid=base.GROUP, prefix="/settlement/")
        os.write(write, b"1")
        os.close(write)
        server.serve_forever(poll_interval=0.1)
    return base.fork_service(2006, "settlement", run)


def open_broker(attempt, grant, call, request, card, binding, identity_case):
    def run(write):
        from gateway_custody import (PrivateCaptureOpenClient, PrivateCustodyServer,
                                     ProtectedGatewayAcquisitionAuthority)
        from gateway_transport import PrivateGatewayClient, ProtectedGatewayTransport
        from linux_runner import LinuxRunnerRefused, PrivateRootSupervisorClient
        from physical_settlement import PrivateSettlementClient
        from protected_spending_control import ControlRefused, PrivateSpendingClient

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
        try:
            response = transport.exchange_reserved(attempt, grant, call, request)
        except ControlRefused as failure:
            base.require(identity_case != "matching" and str(failure) == "gateway_outcome_unknown",
                         "unexpected gateway refusal")
            from physical_usage import payload_sha256
            if identity_case == "classifier_rejected":
                verified_calls = authority.roots[payload_sha256(binding)][6]
                base.require(len(authority.roots) == 1 and verified_calls == 7,
                             "provider rejection changed owner or physical count")
                server.shutdown()
                thread.join(timeout=3)
                base.require(not thread.is_alive(), "provider rejection broker did not join")
                server.server_close()
                (Path(base.GATEWAY).parent / "result.json").write_text(base.canonical({
                    "provider_refusal": True, "root_deadline_ms": observed["root_deadline_ms"],
                    "verified_physical_calls": verified_calls,
                }))
                return
            if identity_case == "responses_executor":
                deadline = time.monotonic() + 5
                path = Path(EXCHANGE).parent / "responses-result.json"
                while not path.is_file():
                    base.require(time.monotonic() < deadline, "direct Responses receipt missing")
                    time.sleep(0.05)
                direct = json.loads(path.read_text())
                response = direct.get("response")
                base.require(direct.get("case") == "responses_executor" and type(response) is dict
                             and set(response) == {"call_id", "request_sha256", "scope_sha256", "physical_manifest_sha256"}
                             and all(response[key] == call[key] for key in ("call_id", "request_sha256", "scope_sha256")),
                             "direct Responses receipt identity differs")
                verified_calls = authority.roots[payload_sha256(binding)][6]
                base.require(len(authority.roots) == 1 and verified_calls == 7,
                             "direct Responses changed acquired owner or call count")
                settlement = PrivateSettlementClient(base.SETTLEMENT, collector_uid=2006, broker_uid=2005,
                                                     worker_uid=2001, owner=base.OWNER, route_sha256=ROUTE,
                                                     tariff_sha256=card.sha256(), mode="rehearsal")
                receipt = settlement.settle(attempt, call, response)
                base.require(receipt["all_calls_complete"] is True and receipt["usage_rated_microusd"] == 31,
                             "direct Responses capture did not settle")
                server.shutdown()
                thread.join(timeout=3)
                base.require(not thread.is_alive(), "direct Responses broker did not join")
                server.server_close()
                (Path(base.GATEWAY).parent / "result.json").write_text(base.canonical({
                    "responses_executor": True, "logical_exchange_success": False,
                    "response": response, "settlement": receipt,
                    "root_deadline_ms": observed["root_deadline_ms"],
                    "verified_physical_calls": verified_calls,
                }))
                return
            base.require(len(authority.roots) == 1, "identity refusal acquired another owner")
            verified_calls = authority.roots[payload_sha256(binding)][6]
            base.require(verified_calls == 5, "identity refusal changed owned warmup call count")
            server.shutdown()
            thread.join(timeout=3)
            base.require(not thread.is_alive(), "broker server did not join after refusal")
            server.server_close()
            (Path(base.GATEWAY).parent / "result.json").write_text(base.canonical({
                "identity_refusal": True, "identity_case": identity_case,
                "root_deadline_ms": observed["root_deadline_ms"],
                "verified_physical_calls": verified_calls,
            }))
            return
        base.require(identity_case == "matching", "changed identity returned success")
        base.require(b"public result" in response["sse"], "retained-route Bifrost output missing")
        from physical_usage import payload_sha256
        base.require(len(authority.roots) == 1, "exchange acquired another owner")
        verified_calls = authority.roots[payload_sha256(binding)][6]
        base.require(verified_calls == EXPECTED_PHYSICAL_CALLS, "physical wallet and Root verification missing")
        settlement = PrivateSettlementClient(base.SETTLEMENT, collector_uid=2006, broker_uid=2005,
                                             worker_uid=2001, owner=base.OWNER,
                                             route_sha256=ROUTE, tariff_sha256=card.sha256(), mode="rehearsal")
        receipt = settlement.settle(attempt, call, response)
        base.require(receipt["all_calls_complete"] is True and receipt["usage_rated_microusd"] == 31,
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
    identity_case = Path("/SFACTORY_WALLET_IDENTITY_CASE").read_text().strip()
    base.require(identity_case in IDENTITY_CASES, "invalid identity fixture case")
    from factory_harness import canonical
    from gateway_custody import root_binding
    from linux_supervisor import factory_scope_digest
    from physical_usage import UsageSchemaProfile
    from protected_spending_control import binding_digest
    from usage_rating import TariffCard, TariffRate

    card = TariffCard("1", "constant_peak", "https://example.org/pricing", "b" * 64,
                      1, 1, 2**63 - 1, tuple(
                          TariffRate(provider, model, "0.0000001", "0.0000001",
                                     "0.0000001", output, "0")
                          for provider, model, output in (
                              ("ollama-cloud", "deepseek-v4-pro:0813", "0.0000002"),
                              ("ollama-cloud", "deepseek-v4.1-flash:1017", "0.0000002"),
                              ("vercel-classifier", "openai/gpt-6-luna", "0.0000002"),
                              ("vercel-classifier", "openai/text-embedding-3-small", "0"),
                          )
                      ))
    profiles = (
        UsageSchemaProfile("embedding-v1", "vercel-classifier", "openai/text-embedding-3-small",
                           ("embedding",), "a" * 64, "usage.prompt_tokens", None,
                           "embedding_no_output", None, None, None),
        UsageSchemaProfile("classifier-chat-v1", "vercel-classifier", "openai/gpt-6-luna",
                           ("classifier",), "a" * 64, "usage.prompt_tokens", "usage.completion_tokens",
                           "inclusive_output_total", None, None, None),
        *(UsageSchemaProfile("answer-chat-v1", "ollama-cloud", model, roles, "a" * 64,
                             "usage.prompt_tokens", "usage.completion_tokens",
                             "inclusive_output_total", None, None, None)
          for model, roles in (("deepseek-v4-pro:0813", ("answer",)),
                               ("deepseek-v4.1-flash:1017", ("fallback",)))),
    )
    if identity_case == "responses_executor":
        profiles = tuple(profile for profile in profiles if profile.provider != "vercel-classifier"
                         or profile.model != "openai/gpt-6-luna") + (
            UsageSchemaProfile("classifier-responses-v1", "vercel-classifier", "openai/gpt-6-luna",
                               ("classifier",), "a" * 64, "usage.input_tokens", "usage.output_tokens",
                               "inclusive_output_total", None, None, None),
        )
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
                           "components": [{"id": "embedding", "max_charge_microusd": 60_000},
                                          {"id": "classifier", "max_charge_microusd": 10_000},
                                          {"id": "classifier_responses", "max_charge_microusd": 10_000},
                                          {"id": "answer", "max_charge_microusd": 20_000},
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
            "review_sha256": REVIEW, "scope": scope, "identity_case": identity_case,
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
        children["capture"] = open_capture(profiles, card, ROUTE)
        children["settler"] = open_settlement(profiles, card, ROUTE)
        children["broker"] = open_broker(attempt, grant, call, request, card, binding, identity_case)
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
        if identity_case == "classifier_rejected":
            base.require(result.get("provider_refusal") is True, "provider rejection result missing")
            base.require(processes["gateway"].wait(timeout=10) == 0, "provider rejection assertions failed")
            observed = json.loads((Path(EXCHANGE).parent / "provider-result.json").read_text())
            base.require(observed.get("case") == identity_case and observed.get("poisoned") is True
                         and observed.get("provider_calls") == 7 and observed.get("embeddings") == 6
                         and observed.get("classifiers") == 1 and observed.get("responses") == 0
                         and observed.get("answers") == 0 and observed.get("owner_observed") == 7,
                         "unknown classifier rejection dispatched a fallback or answer")
            base.require(base.actor(2005, lambda: base.post(base.WALLET, "begin", call))[0] == 409,
                         "unknown classifier rejection allowed repeated begin")
            next_call = call | {"call_id": "after-classifier-rejection", "sequence": 1}
            base.require(base.actor(2005, lambda: base.post(base.WALLET, "verify_inflight", call)) == [200, True],
                         "classifier rejection changed the reserved unknown call or its spending totals")
            base.require(base.actor(2005, lambda: base.post(base.WALLET, "reserve", next_call))[0] == 409,
                         "unknown classifier rejection admitted a new unresolved sequence")
            with sqlite3.connect(base.DATABASE, timeout=1) as db:
                rows = db.execute("SELECT binding, closure, audit FROM roots").fetchall()
            base.require(len(rows) == 1 and json.loads(rows[0][0]) == binding
                         and rows[0][1] is None and rows[0][2] is None,
                         "unknown classifier rejection created successful capture or audit")
            print(base.canonical({
                "schema": 1, "component": "retained_classifier_rejection", "mode": "rehearsal",
                "owner_acquisitions": 1, "verified_physical_calls": 7,
                "embedding_calls": 6, "classifier_chat_calls": 1,
                "responses_http_calls": 0, "answer_http_calls": 0,
                "gateway_poisoned": True, "repeated_begin_denied": True,
                "spent_allowance_not_restored": True, "unresolved_sequence_blocks_admission": True,
                "successful_capture_absent": True,
                "public_route_review_provider_and_charge_bounds_synthetic": True,
                "paid_calls": 0, "live_attempts": 0, "production_admission": False,
                "binary_sha256": {name: digest("/opt/" + name) for name in
                                  ("runtime", "restate-server", "wallet-gateway-test")},
                "fixture_sha256": digest("/opt/wallet-gateway-join.py"),
            }), flush=True)
            return
        if identity_case == "responses_executor":
            base.require(result.get("responses_executor") is True and result.get("logical_exchange_success") is False,
                         "direct Responses result incorrectly reports logical success")
            base.require(processes["gateway"].wait(timeout=10) == 0, "direct Responses assertions failed")
            direct = json.loads((Path(EXCHANGE).parent / "responses-result.json").read_text())
            base.require(direct.get("case") == "responses_executor" and direct.get("store_false") is True
                         and direct.get("provider_calls") == 7 and direct.get("embeddings") == 5
                         and direct.get("responses") == 1 and direct.get("classifiers") == 0
                         and direct.get("answers") == 1 and direct.get("owner_observed") == 7
                         and direct.get("response") == result["response"], "direct Responses physical result differs")
            base.require(base.actor(2005, lambda: base.post(base.WALLET, "begin", call))[0] == 409,
                         "direct Responses allowed repeated begin")
            next_call = call | {"call_id": "after-direct-responses", "sequence": 1}
            base.require(base.actor(2005, lambda: base.post(base.WALLET, "reserve", next_call)) == [200, "Denied"],
                         "direct Responses restored reserved allowance")
            with sqlite3.connect(base.DATABASE, timeout=1) as db:
                rows = db.execute("SELECT binding, closure, audit FROM roots").fetchall()
            base.require(len(rows) == 1 and all(rows[0]), "direct Responses capture or audit missing")
            stored_binding, closure, audit = (json.loads(value) for value in rows[0])
            physical = closure["snapshot"]["calls"]
            base.require(stored_binding == binding and closure["snapshot"]["sealed"] is True
                         and closure["snapshot"]["complete"] is True and len(physical) == 7
                         and set(closure["component_calls"]) == {"embedding", "classifier_responses", "answer"}
                         and len(closure["component_calls"]["embedding"]) == 5
                         and len(closure["component_calls"]["classifier_responses"]) == 1
                         and len(closure["component_calls"]["answer"]) == 1
                         and set(closure["absent_components"]) == {"classifier", "fallback"}
                         and all(item["state"] == "complete" and item["status_code"] == 200 for item in physical)
                         and all(item["role"] == "embedding" and item["provider"] == "vercel-classifier"
                                 and item["model"] == "openai/text-embedding-3-small" for item in physical[:5])
                         and [item["usage"].get("usage.prompt_tokens") for item in physical[:5]] == [64, 64, 64, 64, 44]
                         and physical[5]["role"] == "classifier" and physical[5]["provider"] == "vercel-classifier"
                         and physical[5]["model"] == "openai/gpt-6-luna"
                         and physical[5]["usage"].get("usage.input_tokens") == 1
                         and physical[5]["usage"].get("usage.output_tokens") == 1
                         and physical[6]["role"] == "answer" and physical[6]["provider"] == "ollama-cloud"
                         and physical[6]["model"] == "deepseek-v4-pro:0813"
                         and physical[6]["usage"].get("usage.prompt_tokens") == 1
                         and physical[6]["usage"].get("usage.completion_tokens") == 1
                         and audit["usage_rated_microusd"] == 31
                         and audit["capture_sha256"] == result["response"]["physical_manifest_sha256"],
                         "direct Responses capture was not independently rated")
            print(base.canonical({
                "schema": 1, "component": "owned_responses_executor_capture", "mode": "rehearsal",
                "actual_governance_core_and_wire_authorizer": True, "owner_acquisitions": 1,
                "verified_physical_calls": 7, "store_false_on_wire": True,
                "actual_sdk_answer_stream_drained": True,
                "complete_capture_independently_audited": True, "settled_usage_rated_microusd": 31,
                "logical_exchange_success": False, "ordinary_handler_or_fallback_verified": False,
                "spent_allowance_not_restored": True, "repeated_begin_denied": True,
                "public_route_review_provider_and_charge_bounds_synthetic": True,
                "paid_calls": 0, "live_attempts": 0, "production_admission": False,
                "binary_sha256": {name: digest("/opt/" + name) for name in
                                  ("runtime", "restate-server", "wallet-gateway-test")},
                "fixture_sha256": digest("/opt/wallet-gateway-join.py"),
            }), flush=True)
            return
        if identity_case != "matching":
            base.require(result.get("identity_refusal") is True
                         and result.get("identity_case") == identity_case,
                         "identity refusal result missing")
            base.require(processes["gateway"].wait(timeout=10) == 0,
                         "identity refusal assertions failed")
            observed = json.loads((Path(EXCHANGE).parent / "identity-result.json").read_text())
            base.require(observed.get("case") == identity_case and observed.get("cancelled") is True
                         and observed.get("poisoned") is True and observed.get("cancelled_before_handler") is True
                         and observed.get("provider_calls") == 5 and observed.get("embeddings") == 5
                         and observed.get("classifiers") == 0 and observed.get("answers") == 0
                         and observed.get("owner_observed") == 5,
                         "identity change did not cancel before further provider HTTP")
            base.require(base.actor(2005, lambda: base.post(base.WALLET, "begin", call))[0] == 409,
                         "identity refusal allowed repeated begin")
            next_call = call | {"call_id": "after-identity-refusal", "sequence": 1}
            base.require(base.actor(2005, lambda: base.post(base.WALLET, "verify_inflight", call)) == [200, True],
                         "identity refusal changed the reserved unknown call or its spending totals")
            base.require(base.actor(2005, lambda: base.post(base.WALLET, "reserve", next_call))[0] == 409,
                         "identity refusal admitted a new unresolved sequence")
            with sqlite3.connect(base.DATABASE, timeout=1) as db:
                rows = db.execute("SELECT binding, closure, audit FROM roots").fetchall()
            base.require(len(rows) == 1 and json.loads(rows[0][0]) == binding
                         and rows[0][1] is None and rows[0][2] is None,
                         "identity refusal created a successful capture or audit")
            print(base.canonical({
                "schema": 1, "component": "retained_runtime_identity_refusal", "mode": "rehearsal",
                "identity_case": identity_case, "owner_acquisitions": 1,
                "verified_physical_calls": result["verified_physical_calls"],
                "provider_calls_after_identity_change": 0, "context_cancelled": True,
                "gateway_poisoned": True, "repeated_begin_denied": True,
                "spent_allowance_not_restored": True, "unresolved_sequence_blocks_admission": True,
                "successful_capture_absent": True,
                "authority_and_provider_inputs_synthetic": True, "paid_calls": 0,
                "live_attempts": 0, "production_admission": False,
                "binary_sha256": {name: digest("/opt/" + name) for name in
                                  ("runtime", "restate-server", "wallet-gateway-test")},
                "fixture_sha256": digest("/opt/wallet-gateway-join.py"),
            }), flush=True)
            return
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
        embedding_calls = calls[:6]
        classifier_call, answer_call = calls[6:] if len(calls) == EXPECTED_PHYSICAL_CALLS else ({}, {})
        base.require(
            stored_binding == binding and closure["snapshot"]["sealed"] is True
            and closure["snapshot"]["complete"] is True and len(calls) == EXPECTED_PHYSICAL_CALLS
            and set(closure["component_calls"]) == {"embedding", "classifier", "answer"}
            and len(closure["component_calls"]["embedding"]) == 6
            and len(closure["component_calls"]["classifier"]) == 1
            and len(closure["component_calls"]["answer"]) == 1
            and set(closure["absent_components"]) == {"classifier_responses", "fallback"}
            and all(c["state"] == "complete" and c["status_code"] == 200 for c in calls)
            and all(c["role"] == "embedding" and c["provider"] == "vercel-classifier"
                    and c["model"] == "openai/text-embedding-3-small" for c in embedding_calls)
            and [c["usage"].get("usage.prompt_tokens") for c in embedding_calls] == [64, 64, 64, 64, 44, 2]
            and classifier_call.get("role") == "classifier"
            and classifier_call.get("provider") == "vercel-classifier"
            and classifier_call.get("model") == "openai/gpt-6-luna"
            and classifier_call.get("usage", {}).get("usage.prompt_tokens") == 1
            and classifier_call.get("usage", {}).get("usage.completion_tokens") == 1
            and answer_call.get("role") == "answer"
            and answer_call.get("provider") == "ollama-cloud"
            and answer_call.get("model") == "deepseek-v4-pro:0813"
            and answer_call.get("usage", {}).get("usage.prompt_tokens") == 1
            and answer_call.get("usage", {}).get("usage.completion_tokens") == 1
            and audit["usage_rated_microusd"] == 31
            and audit["capture_sha256"] == result["response"]["physical_manifest_sha256"],
            "captured retained-route physical usage or audit differs",
        )
        base.require(result["root_deadline_ms"] == lease_expiry, "Root deadline lost")
        print(base.canonical({"schema": 1, "component": "wallet_root_broker_bifrost_capture_join", "mode": "rehearsal",
                              "wallet_actual": True, "root_scope_methods_actual": True,
                              "root_constructor_and_registry_synthetic": True,
                              "real_broker_and_capture": True, "actual_bifrost_handler": True,
                              "actual_retained_runtime_and_governance": True,
                              "owned_semantic_warmup_batches": 5,
                              "retained_embedding_calls": 6,
                              "retained_classifier_calls": 1,
                              "retained_answer_calls": 1,
                              "private_listener_joined_and_cancelled": True,
                              "inherited_listener_handoff": True,
                              "gateway_listens_on_bound_socket": True,
                              "actual_immutable_wire_authorizer": True,
                              "public_route_review_provider_and_charge_bounds_synthetic": True,
                              "owner_and_principal_observed_per_callback": True,
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


def public_root_joined_builder_source():
    """Return public Go test-helper source; the gateway binary is unchanged."""
    return r'''//go:build linux
package server
import("testing";"os";"path/filepath";"context";"crypto/sha256";"encoding/json";"fmt";"syscall";"strings";"time";"github.com/stretchr/testify/require";"github.com/maximhq/bifrost/core/schemas";"github.com/maximhq/bifrost/framework/configstore";"github.com/maximhq/bifrost/framework/configstore/tables";"github.com/maximhq/bifrost/plugins/routing/complexity")
func TestPublicRootFixture(t *testing.T){
 base:=os.Getenv("PUBLIC_ROOT_BASE"); require.NotEmpty(t,base); upstream:=os.Getenv("PUBLIC_ROOT_UPSTREAM"); require.NotEmpty(t,upstream)
 cs,review:=factoryJoinedStoreFixture(t,upstream)
 var dbPath string; rows,e:=cs.DB().Raw("PRAGMA database_list").Rows();require.NoError(t,e);for rows.Next(){var seq int;var name,path string;require.NoError(t,rows.Scan(&seq,&name,&path));if name=="main"{dbPath=path}};require.NoError(t,rows.Close())
 schemaRows,e:=cs.DB().Raw("SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name").Rows();require.NoError(t,e);h:=sha256.New();for schemaRows.Next(){var row [4]string;require.NoError(t,schemaRows.Scan(&row[0],&row[1],&row[2],&row[3]));raw,_:=json.Marshal(row);h.Write(raw);h.Write([]byte{'\n'})};require.NoError(t,schemaRows.Close());require.NoError(t,cs.Close(context.Background()))
 state:=filepath.Join(base,"gateway-state");require.NoError(t,os.Mkdir(state,0700));require.NoError(t,os.Chown(state,2007,2007));dest:=filepath.Join(state,"public.db");require.NoError(t,os.Rename(dbPath,dest));require.NoError(t,os.Chmod(dest,0600));require.NoError(t,os.Chown(dest,2007,2007));var st syscall.Stat_t;require.NoError(t,syscall.Stat(dest,&st));pathHash:=sha256.Sum256([]byte(dest));identity:=configstore.FactoryGatewayDatabaseIdentity{PathSHA256:fmt.Sprintf("%x",pathHash),Device:uint64(st.Dev),Inode:st.Ino,SchemaSHA256:fmt.Sprintf("%x",h.Sum(nil))}
 policy,e:=loadLocalNormalizationConfig(factoryOwnedRuntimePolicy(t,upstream));require.NoError(t,e)
 now:=uint64(time.Now().UnixMilli());tariff:=strings.Repeat("d",64)
 allowance:=schemas.FactoryScopeV2{Task:"01K00000000000000000000001",Attempt:1,Generation:"01K00000000000000000000000",Worker:"public-worker",LeaseSHA256:strings.Repeat("a",64),IssuedAtMS:now-1000,ExpiresAtMS:now+600000,Route:schemas.FactoryRouteV2{RouteSHA256:strings.Repeat("e",64),ReviewSHA256:strings.Repeat("c",64),UsageTariffSHA256:&tariff,ValidFromMS:now-1000,ValidUntilMS:now+600000,MaxRequestBytes:65536,MaxOutputTokens:16,Components:[]schemas.FactoryChargeV2{{ID:"embedding",MaxChargeMicrousd:60000},{ID:"classifier",MaxChargeMicrousd:10000},{ID:"classifier_responses",MaxChargeMicrousd:10000},{ID:"answer",MaxChargeMicrousd:20000},{ID:"fallback",MaxChargeMicrousd:1}}}}
 wire:=factoryOwnedWireFixture(allowance,upstream,16)
 template:=map[string]any{"store_path":dest,"store":identity,"review":review,"wire":wire,"wire_sha256":factoryBootstrapTestDigest(wire),"policy":policy,"policy_sha256":factoryBootstrapTestDigest(policy),"broker_path":filepath.Join(base,"broker/socket"),"capture_path":filepath.Join(base,"capture/socket")}
 for name,value:=range map[string]any{"template.json":template,"allowance.json":allowance}{raw,e:=json.Marshal(value);require.NoError(t,e);require.NoError(t,os.WriteFile(filepath.Join(base,name),raw,0600))}
}

func factoryJoinedStoreFixture(t *testing.T, base string) (*configstore.RDBConfigStore, factoryGatewayBootstrapReview) {
	t.Helper()
	cs, review := factoryBootstrapFixture(t, base)
	accounts := map[schemas.ModelProvider]configstore.ProviderConfig{}
	for _, name := range []schemas.ModelProvider{"ollama-cloud", "vercel-classifier"} {
		cfg, err := cs.GetProviderConfig(t.Context(), name)
		require.NoError(t, err)
		cfg.NetworkConfig.AllowPrivateNetwork = true
		require.NoError(t, cs.UpdateProvidersConfig(t.Context(), map[schemas.ModelProvider]configstore.ProviderConfig{name: *cfg}))
		cfg, err = cs.GetProviderConfig(t.Context(), name)
		require.NoError(t, err)
		accounts[name] = *cfg
	}
	input, output, zero := 0.0000001, 0.0000002, 0.0
	prices := []tables.TableModelPricing{}
	for _, target := range []struct{ provider, model, mode string }{{"ollama-cloud", "deepseek-v4-pro:0813", "chat"}, {"ollama-cloud", "deepseek-v4.1-flash:1017", "chat"}, {"vercel-classifier", "openai/gpt-6-luna", "chat"}, {"vercel-classifier", "openai/gpt-6-luna", "responses"}, {"vercel-classifier", "openai/text-embedding-3-small", "embedding"}} {
		out := &output
		if target.mode == "embedding" {
			out = &zero
		}
		prices = append(prices, tables.TableModelPricing{Provider: target.provider, Model: target.model, Mode: target.mode, InputCostPerToken: &input, OutputCostPerToken: out, CacheReadInputTokenCost: &input, CacheCreationInputTokenCost: &input, MaxInputTokens: schemas.Ptr(8192), MaxOutputTokens: schemas.Ptr(512)})
	}
	require.NoError(t, cs.UpsertModelPricesBatch(t.Context(), prices))
	review.AccountSHA256 = factoryBootstrapTestDigest(accounts)
	analyzer := complexity.DefaultAnalyzerConfig()
	corpus := []struct{ Tier, Phrase string }{}
	for _, tier := range []string{"SIMPLE", "MEDIUM", "COMPLEX"} {
		for i := 0; i < 50; i++ {
			phrase := fmt.Sprintf("%s public normalized exemplar %03d", strings.ToLower(tier), i)
			switch tier {
			case "SIMPLE":
				analyzer.Keywords.SimpleKeywords = append(analyzer.Keywords.SimpleKeywords, phrase)
			case "MEDIUM":
				analyzer.Keywords.MediumKeywords = append(analyzer.Keywords.MediumKeywords, phrase)
			case "COMPLEX":
				analyzer.Keywords.ComplexKeywords = append(analyzer.Keywords.ComplexKeywords, phrase)
			}
			corpus = append(corpus, struct{ Tier, Phrase string }{tier, phrase})
		}
	}
	// Defaults are not part of the reviewed public ordered corpus.
	analyzer.Keywords.SimpleKeywords = analyzer.Keywords.SimpleKeywords[len(analyzer.Keywords.SimpleKeywords)-50:]
	analyzer.Keywords.MediumKeywords = analyzer.Keywords.MediumKeywords[len(analyzer.Keywords.MediumKeywords)-50:]
	analyzer.Keywords.ComplexKeywords = analyzer.Keywords.ComplexKeywords[len(analyzer.Keywords.ComplexKeywords)-50:]
	analyzer.Semantic = &configstore.ComplexitySemanticConfig{Provider: "vercel-classifier", EmbeddingModel: "openai/text-embedding-3-small", VectorStore: "embedded", Fallback: "llm", CountTowardBudgets: true, MinSimilarity: 0.8}
	analyzer.LLM = &configstore.ComplexityLLMConfig{Provider: "vercel-classifier", Model: "openai/gpt-6-luna", CountTowardBudgets: true}
	require.NoError(t, cs.UpdateComplexityAnalyzerConfig(t.Context(), &analyzer))
	normalized, err := complexity.ValidateAndNormalize(&analyzer)
	require.NoError(t, err)
	review.AnalyzerSHA256 = factoryBootstrapTestDigest(normalized)
	review.CorpusSHA256 = factoryBootstrapTestDigest(corpus)
	require.NoError(t, cs.DB().Exec("UPDATE routing_rules SET cel_expression = ?", "model == 'auto' && complexity_tier == 'SIMPLE'").Error)
	require.NoError(t, cs.DB().Exec("UPDATE routing_targets SET model = ?", "deepseek-v4-pro:0813").Error)
	rows, err := cs.GetRoutingRulesByScope(t.Context(), "global", "")
	require.NoError(t, err)
	selected, err := cs.GetRoutingRulesByScope(t.Context(), "virtual_key", review.PrincipalID)
	require.NoError(t, err)
	review.RulesSHA256 = factoryBootstrapTestDigest(append(rows, selected...))
 return cs, review
}
'''


class PublicRootWalletRehearsal:
    """Real wallet/capture services for the genuine public Root fixture.

    Authority inputs and provider responses are public fixtures. The gateway,
    Root methods, journal, custody and settlement are unchanged production code.
    """

    def __init__(self, directory, mode="success"):
        self.directory = directory
        self.mode = mode
        self.processes = []
        self.children = []
        self.calls = []
        self.owner = "public-owner"

    def configure(self, allowance):
        from usage_rating import TariffCard, TariffRate
        from physical_usage import UsageSchemaProfile

        self.card = TariffCard(
            "1", "constant_peak", "https://example.org/pricing", "b" * 64,
            1, 1, 2**63 - 1,
            tuple(TariffRate(provider, model, "0.0000001", "0.0000001",
                            "0.0000001", output, "0")
                  for provider, model, output in (
                      ("ollama-cloud", "deepseek-v4-pro:0813", "0.0000002"),
                      ("ollama-cloud", "deepseek-v4.1-flash:1017", "0.0000002"),
                      ("vercel-classifier", "openai/gpt-6-luna", "0.0000002"),
                      ("vercel-classifier", "openai/text-embedding-3-small", "0"))))
        self.profiles = (
            UsageSchemaProfile("embedding-v1", "vercel-classifier", "openai/text-embedding-3-small",
                               ("embedding",), "a" * 64, "usage.prompt_tokens", None,
                               "embedding_no_output", None, None, None),
            UsageSchemaProfile("classifier-chat-v1", "vercel-classifier", "openai/gpt-6-luna",
                               ("classifier",), "a" * 64, "usage.prompt_tokens", "usage.completion_tokens",
                               "inclusive_output_total", None, None, None),
            *(UsageSchemaProfile("answer-chat-v1", "ollama-cloud", model, roles, "a" * 64,
                                 "usage.prompt_tokens", "usage.completion_tokens",
                                 "inclusive_output_total", None, None, None)
              for model, roles in (("deepseek-v4-pro:0813", ("answer",)),
                                   ("deepseek-v4.1-flash:1017", ("fallback",)))),
        )
        allowance["route"]["usage_tariff_sha256"] = self.card.sha256()
        allowance["expires_at_ms"] = min(time.time_ns() // 1_000_000 + 150_000,
                                          (time.time_ns() // 86_400_000_000_000 + 1) * 86_400_000)
        self.allowance = allowance
        if self.mode == "missing-classifier":
            with sqlite3.connect(self.directory / "gateway-state/public.db") as db:
                cursor = db.execute("DELETE FROM governance_virtual_key_provider_configs WHERE virtual_key_id=? AND provider=?",
                                    ("public-principal", "vercel-classifier"))
                assert cursor.rowcount == 1
                assert db.execute("SELECT count(*) FROM governance_virtual_key_provider_configs WHERE virtual_key_id=? AND provider=?",
                                  ("public-principal", "vercel-classifier")).fetchone() == (0,)
        return allowance

    def provider(self, handler):
        body = json.loads(handler.rfile.read(int(handler.headers["Content-Length"])))
        model = body.get("model")
        self.calls.append({"path": handler.path, "model": model})
        if self.mode == "provider-unknown" and model == "deepseek-v4-pro:0813" and sum(
                row["model"] == model for row in self.calls) == 3:
            (self.directory / "joined-provider-progress.json").write_text(base.canonical(self.calls))
            handler.connection.shutdown(socket.SHUT_RDWR)
            handler.connection.close()
            return
        (self.directory / "joined-provider-progress.json").write_text(base.canonical(self.calls))
        handler.send_response(200)
        if handler.path == "/v1/embeddings":
            texts = body["input"]
            texts = texts if isinstance(texts, list) else [texts]
            data = []
            for index, _ in enumerate(texts):
                vector = [0.0] * 1536
                vector[index % 3 if len(texts) > 1 else 3] = 1.0
                data.append({"object": "embedding", "index": index, "embedding": vector})
            result = {"object": "list", "model": model, "data": data,
                      "usage": {"prompt_tokens": 2 * len(texts), "total_tokens": 2 * len(texts)}}
            raw = json.dumps(result).encode()
            handler.send_header("Content-Type", "application/json")
        elif model == "openai/gpt-6-luna":
            result = {"id": "public-classifier", "object": "chat.completion", "model": model,
                      "choices": [{"index": 0, "finish_reason": "stop", "message": {
                          "role": "assistant", "content": '{"tier":"SIMPLE","reasoning":"public fixture"}'}}],
                      "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
            raw = json.dumps(result).encode()
            handler.send_header("Content-Type", "application/json")
        else:
            assert handler.path == "/v1/chat/completions" and model == "deepseek-v4-pro:0813"
            events = [
                {"choices": [{"index": 0, "delta": {"content": "public result"}, "finish_reason": None}]},
                {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
                {"choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}},
            ]
            raw = "".join("data: " + json.dumps({"id": "public", "object": "chat.completion.chunk",
                                               "created": 1, "model": model, **event}) + "\n\n"
                          for event in events).encode() + b"data: [DONE]\n\n"
            handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)

    def start_services(self):
        owned = self.directory
        base.OWNER = self.owner
        base.GROUP = 2007
        base.PREFIX = str(owned / "w")
        base.WALLET = str(owned / "owner/socket")
        base.BACKEND = str(owned / "w/wallet/backend/journal.sock")
        base.GATEWAY = str(owned / "broker/socket")
        base.CAPTURE = str(owned / "capture/socket")
        base.SETTLEMENT = str(owned / "settlement/socket")
        base.DATABASE = str(owned / "w/capture/state/capture.db")
        for path, uid, gid, mode in (
            (Path("/logs"), 0, 0, 0o700),
            (owned / "w", 0, 0, 0o755),
            (owned / "w/wallet", 0, 0, 0o755),
            (owned / "w/wallet/state", 2004, 2004, 0o700),
            (Path(base.BACKEND).parent, 2004, 2004, 0o700),
            (owned / "owner", 2004, 2004, 0o755),
            (owned / "broker", 2005, 2007, 0o750),
            (owned / "capture", 2008, 2007, 0o750),
            (owned / "settlement", 2006, base.GROUP, 0o750),
            (owned / "w/capture", 0, 0, 0o755),
            (Path(base.DATABASE).parent, 2008, 2008, 0o700),
        ):
            path.mkdir(exist_ok=True)
            path.chmod(mode)
            os.chown(path, uid, gid)
        self.start_wallet()
        now = time.time_ns() // 1_000_000
        self.bootstrap = {
            "owner": self.owner, "policy_sha256": "a" * 64,
            "predecessor_fence_sha256": "b" * 64, "inventory_sha256": "c" * 64,
            "observed_at_ms": now, "approved_daily_cap_microusd": 5_000_000,
            "daily_cap_microusd": 5_000_000, "opening_tasks": {TASK: 0, DAY_FILL_TASK: 750_000},
            "opening_days": {str(now // 86_400_000): 750_000}, "scopes": []}
        assert base.post(base.WALLET, "initialize", self.bootstrap)[0] == 200
        self.children.append(open_capture(self.profiles, self.card, ROUTE,
            lost_ack_call="logical-2" if self.mode == "capture-unknown" else None))
        self.children.append(open_settlement(self.profiles, self.card, ROUTE))

    def start_wallet(self):
        sdk = base.start_binary(["/opt/runtime", "sdk", "127.0.0.1:19080"], "sdk")
        self.processes.append(sdk)
        deadline = time.monotonic() + 15
        while True:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", 19080)) == 0:
                    break
            assert sdk.poll() is None and time.monotonic() < deadline
            time.sleep(0.05)
        journal, ports = base.start_journal()
        self.processes.append(journal)
        assert base.tcp_post(ports["admin-api-server"], "/deployments",
                             {"uri": "http://127.0.0.1:19080", "force": False, "breaking": False})[0] in (200, 201)
        self.backend_pid = base.start_backend(ports["http-ingress-server"])
        self.children.append(self.backend_pid)
        self.processes.append(base.start_frontend())

    def start_broker(self, cfg, prepare, result_path):
        def run(write):
            from gateway_custody import PrivateCaptureOpenClient, PrivateCustodyServer, ProtectedGatewayAcquisitionAuthority
            from gateway_transport import PrivateGatewayClient, ProtectedGatewayTransport
            from linux_runner import PrivateRootSupervisorClient
            from linux_supervisor import factory_scope_digest
            from physical_settlement import PrivateSettlementClient
            from protected_spending_control import PrivateSpendingClient
            import harness_gateway_public_start_fixture as public

            journal = PrivateSpendingClient(base.WALLET, service_uid=2004, broker_uid=2005, owner=self.owner)
            capture = PrivateCaptureOpenClient(base.CAPTURE, service_uid=2008, broker_uid=2005, owner=self.owner)
            authority = ProtectedGatewayAcquisitionAuthority(journal, capture, gateway_uid=2007)
            server = PrivateCustodyServer(base.GATEWAY, authority, service_uid=2005,
                                          socket_gid=2007, prefix="/gateway/")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            os.write(write, b"1")
            os.close(write)
            signal_path = self.directory / "broker-start"
            deadline = time.monotonic() + 25
            while not signal_path.exists():
                assert time.monotonic() < deadline
                time.sleep(0.02)
            public.broker(cfg["socket_path"], prepare, result_path)
            started = json.loads(result_path.read_bytes())
            if self.mode == "missing-classifier":
                assert started["status"] == 503 and not authority.roots
                server.shutdown()
                thread.join(timeout=3)
                assert not thread.is_alive()
                server.server_close()
                return
            assert started["status"] == started["observed_status"] == 200, started
            assert not (self.directory / "joined-provider-progress.json").exists(), "cold start called provider"
            native_grant = started["grant"]
            grant = {"attempt_id": native_grant["attempt_id"], "owner": self.owner,
                     "route_sha256": ROUTE, "tariff_sha256": self.card.sha256(),
                     "scope_sha256": factory_scope_digest(self.allowance),
                     "expires_at_ms": native_grant["expires_at_ms"]}
            attempt = prepare["attempt"]
            root = PrivateRootSupervisorClient(cfg["socket_path"], broker_uid=2005)
            transport = ProtectedGatewayTransport(
                journal, authority, PrivateGatewayClient("/var/lib/sfactory-harness/gw/" + native_grant["attempt_id"][4:] + ".sock", gateway_uid=2007,
                                                         broker_uid=2005, owner=self.owner),
                route_sha256=ROUTE, tariff_sha256=self.card.sha256(), mode="rehearsal", scope_client=root)
            settlement = PrivateSettlementClient(base.SETTLEMENT, collector_uid=2006, broker_uid=2005,
                worker_uid=2001, owner=self.owner, route_sha256=ROUTE,
                tariff_sha256=self.card.sha256(), mode="rehearsal")
            results = []
            for sequence in range(2 if self.mode == "success" else 3):
                request = {"model": "auto", "messages": [{"role": "user", "content": "public " + str(sequence)}],
                           "tools": [], "max_tokens": 16, "stream": True, "stream_options": {"include_usage": True}}
                call = {"call_id": "logical-" + str(sequence), "scope_sha256": grant["scope_sha256"],
                        "request_sha256": digest_value(request), "sequence": sequence,
                        "request_bytes": len(base.canonical(request).encode()), "output_tokens": 16}
                assert journal("reserve", call) == "Reserved"
                try:
                    response = transport.exchange_reserved(attempt, grant, call, request)
                except Exception as error:
                    from protected_spending_control import ControlRefused
                    assert self.mode != "success" and sequence == 2 and isinstance(error, ControlRefused)
                    assert str(error) == "gateway_outcome_unknown"
                    assert journal("verify_inflight", call) is True
                    try:
                        journal("begin", call)
                    except ControlRefused:
                        pass
                    else:
                        raise AssertionError("unknown dispatch rearmed")
                    next_call = call | {"call_id": "after-unknown", "sequence": sequence + 1}
                    try:
                        journal("reserve", next_call)
                    except ControlRefused:
                        pass
                    else:
                        raise AssertionError("unknown dispatch admitted another sequence")
                    (result_path.parent / "joined-unknown.json").write_text(base.canonical({
                        "mode": self.mode, "call": call, "next_call": next_call,
                        "acquired_roots": len(authority.roots),
                        "verified_physical_calls": [row[6] for row in authority.roots.values()]}))
                    break
                assert b"public result" in response["sse"]
                receipt = settlement.settle(attempt, call, response)
                assert receipt["all_calls_complete"] is True
                results.append({"call": call, "response": {k: v for k, v in response.items() if k != "sse"},
                                "settlement": receipt})
            assert len(authority.roots) == (2 if self.mode == "success" else 3)
            counts = sorted(row[6] for row in authority.roots.values())
            assert counts == ([3, 8] if self.mode == "success" else [3, 3, 8]), counts
            (result_path.parent / "joined-exchanges.json").write_text(base.canonical({
                "exchanges": results, "physical_calls_per_new_owner": counts,
                "owner_acquisitions": len(authority.roots), "native_grant_sha256": digest_value(native_grant),
                "same_runtime": True}))
            server.shutdown()
            thread.join(timeout=3)
            assert not thread.is_alive()
            server.server_close()
        original_drop = base.drop

        def broker_identity(uid):
            assert uid == 2005
            os.setgroups([2001, 2007])
            os.setgid(uid)
            os.setuid(uid)

        base.drop = broker_identity
        try:
            self.broker_pid = base.fork_service(2005, "joined-broker", run)
        finally:
            base.drop = original_drop
        return self.broker_pid

    def wrong_broker(self, cfg, prepare):
        original_drop = base.drop

        def attacker(uid):
            assert uid == 2006
            os.setgroups([2005, 2007])  # Reach the socket; kernel UID must still deny.
            os.setgid(uid)
            os.setuid(uid)

        base.drop = attacker
        try:
            observed = base.actor(2006, lambda: base.post(
                cfg["socket_path"], "prepare", prepare, prefix="/harness-launch/"))
        finally:
            base.drop = original_drop
        assert observed == [503, None], observed
        (self.directory / "wrong-broker.json").write_text(base.canonical({
            "uid": 2006, "primary_gid": 2006, "supplementary_gids": [2005, 2007],
            "public_prepare_status": 503, "consumed_intent_created": False}))

    def verify_restart(self):
        from linux_supervisor import factory_scope_digest

        results = json.loads((self.directory / "broker-result/joined-exchanges.json").read_bytes())
        with sqlite3.connect(base.DATABASE) as db:
            rows = db.execute("SELECT binding, closure, audit FROM roots ORDER BY id").fetchall()
        completed = [(json.loads(binding), json.loads(closure), json.loads(audit))
                     for binding, closure, audit in rows if closure is not None and audit is not None]
        assert len(completed) == 2
        assert sorted(len(closure["snapshot"]["calls"]) for _, closure, _ in completed) == [3, 8]
        assert {binding["call_id"] for binding, _, _ in completed} == {"logical-0", "logical-1"}
        assert len({closure["binding"]["physical_manifest_sha256"] for _, closure, _ in completed}) == 2
        assert all(binding["scope_sha256"] == factory_scope_digest(self.allowance)
                   for binding, _, _ in completed)
        if self.mode != "success":
            assert len(rows) == 3
            unknown = [(binding, closure, audit) for binding, closure, audit in rows
                       if json.loads(binding)["call_id"] == "logical-2"]
            assert len(unknown) == 1 and unknown[0][2] is None
            assert (unknown[0][1] is not None) == (self.mode == "capture-unknown")
        # An independent permanent task starts already exhausted. All six
        # admitted attempt identities retain that same exhausted allowance.
        denied = []
        for attempt in range(1, 7):
            scope = copy.deepcopy(self.allowance)
            scope.update(task=DAY_FILL_TASK, attempt=attempt)
            status, scope_hash = base.post(base.WALLET, "admit_attempt", scope)
            assert status == 200 and scope_hash == factory_scope_digest(scope)
            call = {"call_id": "exhausted-" + str(attempt), "scope_sha256": scope_hash,
                    "request_sha256": "a" * 64, "sequence": 0, "request_bytes": 1, "output_tokens": 1}
            assert base.actor(2005, lambda: base.post(base.WALLET, "reserve", call)) == [200, "Denied"]
            assert base.actor(2005, lambda: base.post(base.WALLET, "begin", call))[0] == 409
            assert base.post(base.WALLET, "revoke", scope_hash)[0] == 200
            denied.append(call)
        for process in reversed(self.processes):
            base.stop_process(process)
        self.processes.clear()
        base.stop_pid(self.backend_pid)
        self.children.remove(self.backend_pid)
        Path("/logs/restate.log").rename("/logs/restate-before-restart.log")
        self.start_wallet()
        assert base.post(base.WALLET, "initialize", self.bootstrap)[0] == 200
        changed = copy.deepcopy(self.bootstrap)
        changed["opening_tasks"][DAY_FILL_TASK] = 0
        assert base.post(base.WALLET, "initialize", changed)[0] == 409
        for call in denied:
            assert base.actor(2005, lambda: base.post(base.WALLET, "reserve", call)) == [200, "Denied"]
            assert base.actor(2005, lambda: base.post(base.WALLET, "begin", call))[0] == 409
        for exchange in results["exchanges"]:
            call = exchange["call"]
            assert base.actor(2005, lambda: base.post(base.WALLET, "begin", call))[0] == 409
        if self.mode != "success":
            unknown = json.loads((self.directory / "broker-result/joined-unknown.json").read_bytes())
            assert base.actor(2005, lambda: base.post(base.WALLET, "begin", unknown["call"]))[0] == 409
            assert base.actor(2005, lambda: base.post(base.WALLET, "reserve", unknown["next_call"]))[0] == 409
            assert base.actor(2005, lambda: base.post(base.WALLET, "verify_inflight", unknown["call"])) == [200, True]
        with sqlite3.connect(self.directory / "gateway-state/public.db") as db:
            principals = sorted({row[1] for row in db.execute("SELECT * FROM normalization_ledger_holds")})
        assert principals == ["public-principal"]
        (self.directory / "joined-restart-proof.json").write_text(base.canonical({
            "mode": self.mode, "completed_capture_roots": [binding for binding, _, _ in completed],
            "canonical_governance_principals": principals, "permanent_allowance_denied_attempts": denied,
            "wallet_restarted_with_same_journal": True, "reset_refused": True,
            "completed_replays_denied": True, "unknown_consumed_after_restart": self.mode != "success"}))

    def finish(self):
        for process in reversed(self.processes):
            base.stop_process(process)
        for child in reversed(self.children):
            base.stop_pid(child)


def digest_value(value):
    return hashlib.sha256(base.canonical(value).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--identity-case", choices=IDENTITY_CASES, default="matching")
    args = parser.parse_args()
    root = args.rootfs
    base.require(os.geteuid() == 0 and root.is_absolute() and root.is_dir() and not root.is_symlink(),
                 "fresh absolute disposable rootfs required")
    base.require((root / MARKER).read_text() == MARKER + "\n", "disposable marker required")
    base.require(not (root / "code").exists() and not (root / "logs").exists()
                 and not (root / base.PREFIX.lstrip("/")).exists(), "fixture already attempted")
    base.require(all((root / "opt" / name).is_file() for name in
                     ("runtime", "restate-server", "wallet-gateway-test")), "fixture binaries missing")
    (root / "SFACTORY_WALLET_IDENTITY_CASE").write_text(args.identity_case + "\n")
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
