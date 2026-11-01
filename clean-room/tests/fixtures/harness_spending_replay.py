#!/usr/bin/env python3
"""Disposable real Restate race/crash checks. No provider, key or live budget.

The direct loopback SDK is intentionally unauthenticated and must never be used
as deployment evidence. The fixture owns every process and journal it touches.
"""

import concurrent.futures
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "target/debug/examples/harness_spending_fixture"
NODE = "/Users/bo/.local/opt/node/bin/node"
PACKAGE = "/Users/bo/.local/opt/node/lib/node_modules/@restatedev/restate-server"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
sys.path.insert(0, str(ROOT / "crates/execution/harness"))
from billing_receipts import BillingRefused, PhysicalCall, freeze_manifest  # noqa: E402
from billing_spending import collect_for_spending  # noqa: E402


def post(url, body):
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with OPENER.open(request, timeout=10) as response:
            raw = response.read(65537)
            assert len(raw) <= 65536
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        error.close()
        return error.code, None


def terminate(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def exercise():
    binary = subprocess.check_output(
        [
            NODE,
            "-p",
            'require.resolve("@restatedev/restate-server-darwin-arm64/bin/restate-server")',
        ],
        cwd=PACKAGE,
        text=True,
        timeout=5,
    ).strip()
    with tempfile.TemporaryDirectory(prefix="sfactory-harness-spending-") as tmp:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            sdk_port = sock.getsockname()[1]
        env = {"PATH": "/usr/bin:/bin", "HOME": tmp, "RUST_LOG": "info"}
        with open(Path(tmp) / "sdk.log", "w") as sdklog:
            sdk = subprocess.Popen(
                [str(SDK), f"127.0.0.1:{sdk_port}"],
                cwd=tmp,
                env=env,
                stdout=sdklog,
                stderr=subprocess.STDOUT,
            )
            server = None

            def start():
                logfile = Path(tmp) / "server.log"
                with logfile.open("w") as log:
                    process = subprocess.Popen(
                        [
                            binary,
                            "--base-dir",
                            tmp + "/state",
                            "--node-name",
                            "harness-spending-fixture",
                            "--bind-ip",
                            "127.0.0.1",
                            "--use-random-ports",
                            "true",
                            "--listen-mode",
                            "tcp",
                            "--no-logo",
                            "--log-format",
                            "json",
                        ],
                        cwd=tmp,
                        env=env,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                try:
                    deadline = time.monotonic() + 25
                    while time.monotonic() < deadline:
                        if process.poll() is not None or sdk.poll() is not None:
                            raise RuntimeError("disposable fixture exited")
                        ports = {}
                        for line in logfile.read_text().splitlines():
                            try:
                                record = json.loads(line)
                            except ValueError:
                                continue
                            if (
                                "listening"
                                in record.get("fields", {}).get("message", "").lower()
                            ):
                                span = record.get("span", {})
                                ports[span.get("server_name")] = span.get("server.port")
                        if ports.get("http-ingress-server") and ports.get(
                            "admin-api-server"
                        ):
                            return (
                                process,
                                ports["http-ingress-server"],
                                ports["admin-api-server"],
                            )
                        time.sleep(0.1)
                    raise RuntimeError("disposable fixture readiness timeout")
                except BaseException:
                    terminate(process)
                    raise

            try:
                server, ingress, admin = start()
                deadline = time.monotonic() + 10
                while True:
                    try:
                        code, _ = post(
                            f"http://127.0.0.1:{admin}/deployments",
                            {"uri": f"http://127.0.0.1:{sdk_port}"},
                        )
                        assert code in (200, 201)
                        break
                    except (OSError, urllib.error.URLError):
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
                now = time.time_ns() // 1_000_000
                day = now // 86_400_000
                route = {
                    "route_sha256": "e" * 64,
                    "review_sha256": "f" * 64,
                    "valid_from_ms": now,
                    "valid_until_ms": now + 300_000,
                    "max_request_bytes": 65536,
                    "max_output_tokens": 100,
                    "components": [
                        {"id": "classifier", "max_charge_microusd": 100000},
                        {"id": "answer", "max_charge_microusd": 200000},
                    ],
                }
                scopes = [
                    {
                        "task": task,
                        "attempt": 1,
                        "generation": "generation",
                        "worker": "worker",
                        "lease_sha256": "d" * 64,
                        "issued_at_ms": now,
                        "expires_at_ms": now + 300_000,
                        "route": route,
                    }
                    for task in ("task", "other", "third", "denied")
                ]
                bootstrap = {
                    "owner": "fixture",
                    "policy_sha256": "a" * 64,
                    "predecessor_fence_sha256": "b" * 64,
                    "inventory_sha256": "c" * 64,
                    "observed_at_ms": now,
                    "approved_daily_cap_microusd": 1000000,
                    "daily_cap_microusd": 1000000,
                    "opening_tasks": {s["task"]: 0 for s in scopes},
                    "opening_days": {str(day): 399998},
                    "scopes": scopes,
                }

                def endpoint(handler):
                    return f"http://127.0.0.1:{ingress}/restate/call/HarnessSpending/fixture/{handler}"

                def call(index, sequence=0):
                    return {
                        "call_id": scopes[index]["task"] + "-" + str(sequence),
                        "scope_sha256": hashlib.sha256(
                            json.dumps(scopes[index], separators=(",", ":")).encode()
                        ).hexdigest(),
                        "request_sha256": "1" * 64,
                        "sequence": sequence,
                        "request_bytes": 1000,
                        "output_tokens": 100,
                    }

                assert post(endpoint("initialize"), bootstrap)[0] == 200
                first = call(0)
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                    reserved = list(
                        pool.map(lambda _: post(endpoint("reserve"), first), range(10))
                    )
                assert reserved == [(200, "Reserved")] * 10, reserved
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                    begun = list(
                        pool.map(lambda _: post(endpoint("begin"), first), range(10))
                    )
                assert begun.count((200, True)) == 1, begun
                assert sum(code == 409 for code, _ in begun) == 9, begun
                assert post(endpoint("reserve"), call(0, 1))[0] == 409
                assert post(endpoint("reserve"), call(1)) == (200, "Reserved")
                # 399998 opening + two 300k calls leave two microUSD headroom.
                # Dropping the opening inventory would wrongly admit this call.
                assert post(endpoint("reserve"), call(2)) == (200, "Denied")
                assert post(endpoint("reserve"), call(3)) == (200, "Denied")
                generations = (
                    "gen_01ARZ3NDEKTSV4RRFFQ69G5FAV",
                    "gen_01ARZ3NDEKTSV4RRFFQ69G5FAW",
                )
                manifest = freeze_manifest(
                    attempt_id="fixture-attempt",
                    parent_request_id="fixture-parent",
                    route_sha256=route["route_sha256"],
                    request_sha256=first["request_sha256"],
                    expected_call_ids=("classifier", "answer"),
                    calls=tuple(
                        PhysicalCall(
                            role,
                            i,
                            role,
                            "openai",
                            "fixture",
                            generation,
                            "vercel_generation",
                        )
                        for i, (role, generation) in enumerate(
                            zip(("classifier", "answer"), generations)
                        )
                    ),
                )

                claims = []

                def authority(method, body):
                    if method == "claim_receipts":
                        claims.append(body.copy())
                    code, result = post(endpoint(method), body)
                    if code != 200:
                        raise RuntimeError("fixture authority denied")
                    return result

                class SyntheticClient:
                    pending = True

                    def lookup(self, generation):
                        if self.pending:
                            raise BillingRefused("receipt_pending")
                        return json.dumps(
                            {
                                "data": {
                                    "id": generation,
                                    "provider_name": "openai",
                                    "model": "fixture",
                                    "is_byok": False,
                                    "total_cost": "0.000001",
                                    "gateway_cost": "0.000001",
                                    "usage": "0.000001",
                                }
                            }
                        ).encode()

                client = SyntheticClient()
                bridge = dict(
                    authority=authority,
                    client=client,
                    call_id=first["call_id"],
                    scope_sha256=first["scope_sha256"],
                    route_sha256=route["route_sha256"],
                    request_sha256=first["request_sha256"],
                    expected_components=("classifier", "answer"),
                    component_calls={
                        "classifier": ("classifier",),
                        "answer": ("answer",),
                    },
                    absent_components={},
                )
                try:
                    collect_for_spending(manifest, **bridge)
                except BillingRefused as error:
                    assert str(error) == "receipt_pending"
                else:
                    raise AssertionError("missing synthetic receipt settled call")
                # Crash only this disposable server. Never retry an inference.
                server.kill()
                server.wait(timeout=10)
                server, ingress, _ = start()
                assert post(endpoint("reserve"), first) == (200, "Unknown")
                assert post(endpoint("begin"), first)[0] == 409
                assert post(endpoint("reserve"), call(0, 1))[0] == 409
                assert post(endpoint("reserve"), call(1)) == (200, "Reserved")
                assert post(endpoint("reserve"), call(3)) == (200, "Denied")
                # Check retained claims BEFORE a successful relookup could recreate
                # them. Lost claims would admit this conflicting manifest.
                assert (
                    post(
                        endpoint("claim_receipts"),
                        claims[-1] | {"manifest_sha256": "9" * 64},
                    )[0]
                    == 409
                )
                client.pending = False
                result = collect_for_spending(manifest, **bridge)
                assert result["billed_microusd"] == 2
                assert post(endpoint("reserve"), first) == (200, "Complete")
                # Refunding the first 300k reserve down to actual 2 would leave
                # exactly 700k spent and wrongly admit this next 300k call.
                assert post(endpoint("reserve"), call(0, 1)) == (200, "Denied")
                changed = dict(bootstrap, daily_cap_microusd=2000000)
                assert post(endpoint("initialize"), changed)[0] == 409
                print(
                    json.dumps(
                        {
                            "synthetic": True,
                            "candidate_enabled": False,
                            "live_benchmark_runs": 0,
                            "race_requests": 20,
                            "single_begin": True,
                            "unknown_survived_sigkill": True,
                            "daily_denial_survived_sigkill": True,
                            "opening_spend_retained": True,
                            "collector_claim_survived_sigkill": True,
                            "complete_receipt_settled_same_journal": True,
                            "actual_cost_did_not_refund_reservation": True,
                        },
                        sort_keys=True,
                    )
                )
            finally:
                terminate(server)
                terminate(sdk)


if __name__ == "__main__":
    exercise()
