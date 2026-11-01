# ruff: noqa: E402
#!/usr/bin/env python3
"""Actual pinned Goose + resumable runner + disposable journal/evaluator rehearsal.

Only synthetic provider responses/receipts. No keys, Bifrost, live attempts or
production services. Loopback SDK is a disposable fixture, not private ingress.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crates/execution/harness"))
from billing_receipts import PhysicalCall, freeze_manifest  # noqa: E402
from billing_spending import collect_for_spending  # noqa: E402
from paired_runner import Runner  # noqa: E402
from usage_rating import (
    TariffCard,
    TariffRate,
    UsageRatedCollector,
    UsageEvidence,
    Manifest as RatedManifest,
    PhysicalCall as RatedCall,
)  # noqa: E402
from usage_spending import collect_usage_for_spending  # noqa: E402


from protected_goose_runtime import (
    GOOSE_SHA256,
    ProtectedGooseAdapter,
    profile_fingerprints,
    sha,
)  # noqa: E402
from protected_spending_control import JournaledControl  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "spending_fixture", Path(__file__).with_name("harness_spending_replay.py")
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def synthetic_tariff():
    return TariffCard(
        "synthetic-1",
        "constant_peak",
        "https://example.invalid/synthetic-pricing",
        "a" * 64,
        0,
        0,
        253402300799999,
        (
            TariffRate(
                "openai",
                "fixture",
                "0.0000001",
                "0.00000001",
                "0.0000001",
                "0.0000004",
                "0",
            ),
        ),
    )


PROGRAM = """import hashlib,json,os,pathlib,sys,tempfile
def update(path,replacement):
 if not isinstance(replacement,dict) or any(type(v)!=int or v<0 for v in replacement.values()):raise ValueError()
 path=pathlib.Path(path)
 if not str(path).startswith("scratch/") or ".." in path.parts:raise ValueError()
 fd,tmp=tempfile.mkstemp(dir=path.parent)
 try:
  with os.fdopen(fd,"w") as f:json.dump(replacement,f);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
 return replacement
for line in sys.stdin:
 try:
  v=json.loads(line);print(json.dumps({"result":update(v["path"],v["replacement"])}))
 except Exception:print(json.dumps({"error":"invalid"}))
"""
FILES = {
    "README.md": "Atomic config library and JSON Lines wrapper. Verify: python3 -m unittest discover\n",
    "test_solution.py": "import unittest\nclass Smoke(unittest.TestCase):\n def test_invalid(self):\n  from solution import update\n  with self.assertRaises(ValueError): update('scratch/x.json', {'x':True})\n",
    "solution.py": PROGRAM,
}


def ulid(value):
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    result = ""
    for _ in range(26):
        result = alphabet[value & 31] + result
        value >>= 5
    return result


class RehearsalControl:
    def __init__(self, base, suite, tariff=None):
        self.base, self.scopes, self.receipts, self.serial = base, {}, {}, 0
        self.owner = "paired-fixture"
        self.tariff = tariff
        self.task_attempts = {}
        self.by_scope, self.manifests = {}, {}
        self.policy_sha = hashlib.sha256(
            (
                ROOT / "crates/execution/harness/benchmark-spending-policy.json"
            ).read_bytes()
        ).hexdigest()
        now = time.time_ns() // 1000000
        self.rpc(
            "initialize",
            {
                "owner": self.owner,
                "policy_sha256": self.policy_sha,
                "predecessor_fence_sha256": "b" * 64,
                "inventory_sha256": "c" * 64,
                "observed_at_ms": now,
                "approved_daily_cap_microusd": 5000000,
                "daily_cap_microusd": 5000000,
                "opening_tasks": {t["id"]: 0 for t in suite["tasks"]},
                "opening_days": {str(now // 86400000): 0},
                "scopes": [],
            },
        )

    def rpc(self, method, body):
        code, result = fixture.post(
            self.base + "/restate/call/HarnessSpending/" + self.owner + "/" + method,
            body,
        )
        if code != 200:
            raise RuntimeError("disposable journal refused " + method)
        return result

    def admit(self, attempt):
        if attempt["mode"] != "rehearsal":
            raise RuntimeError("synthetic only")
        now = time.time_ns() // 1000000
        n = self.task_attempts.get(attempt["task_id"], 0) + 1
        scope = {
            "task": attempt["task_id"],
            "attempt": n,
            "generation": attempt["attempt_id"],
            "worker": "synthetic-pinned-goose",
            "lease_sha256": sha(attempt),
            "issued_at_ms": now,
            "expires_at_ms": now + 180000,
            "route": {
                "route_sha256": attempt["route"],
                "review_sha256": "d" * 64,
                "valid_from_ms": now,
                "valid_until_ms": now + 180000,
                "max_request_bytes": 65536,
                "max_output_tokens": 16384,
                "components": [
                    {"id": "classifier", "max_charge_microusd": 100},
                    {"id": "answer", "max_charge_microusd": 900},
                ],
            },
        }
        if self.tariff:
            scope["route"]["usage_tariff_sha256"] = self.tariff.sha256()
        digest = self.rpc("admit_attempt", scope)
        self.scopes[attempt["attempt_id"]] = digest
        self.by_scope[digest] = attempt.copy()
        self.task_attempts[attempt["task_id"]] = n
        return {
            "attempt_id": attempt["attempt_id"],
            "status": "allowed",
            "authority_receipt_sha256": sha(scope),
            "attempt_sha256": sha(attempt),
            "scope_sha256": digest,
            "policy_sha256": self.policy_sha,
            "owner": self.owner,
            "route_sha256": attempt["route"],
            "expires_at_ms": scope["expires_at_ms"],
        } | (
            {"cost_basis": "audited_usage_rated", "tariff_sha256": self.tariff.sha256()}
            if self.tariff
            else {}
        )

    def authorize_tool(self, attempt, scope, name, arguments_sha256):
        if self.scopes.get(attempt["attempt_id"]) != scope or name not in (
            "read_file",
            "write_file",
            "list_files",
        ):
            raise RuntimeError("synthetic tool scope unavailable")
        return {
            "attempt_sha256": sha(attempt),
            "scope_sha256": scope,
            "name": name,
            "arguments_sha256": arguments_sha256,
            "allowed": True,
        }

    def provider_exchange(self, call, body):
        attempt = self.by_scope[call["scope_sha256"]]
        sequence = call["sequence"]
        tools = [m for m in body["messages"] if m.get("role") == "tool"]
        if attempt["variant"] == "candidate" and not tools:
            script = (
                "".join(
                    "await tools.call('write_file',"
                    + json.dumps({"path": k, "content": v})
                    + ");"
                    for k, v in FILES.items()
                )
                + "return 'Files written.';"
            )
            name, args = "run_script", {"script": script}
        elif attempt["variant"] == "baseline" and len(tools) < len(FILES):
            name = "write_file"
            key = list(FILES)[len(tools)]
            args = {"path": key, "content": FILES[key]}
        else:
            name = None
        if name is None:
            delta, finish = (
                {"role": "assistant", "content": "Synthetic project written."},
                "stop",
            )
        else:
            delta = {
                "role": "assistant",
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "tool-" + str(sequence),
                        "type": "function",
                        "function": {
                            "name": "factory__" + name,
                            "arguments": json.dumps(args),
                        },
                    }
                ],
            }
            finish = "tool_calls"
        chunks = [
            {
                "id": "synthetic-" + str(self.serial),
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "auto",
                "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
            },
            {
                "id": "synthetic-" + str(self.serial),
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "auto",
                "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 4,
                    "total_tokens": 14,
                },
            },
        ]
        calls = tuple(
            PhysicalCall(
                role,
                i,
                role,
                "openai",
                "fixture",
                "gen_" + ulid(self.serial * 2 + i + 1),
                "vercel_generation",
            )
            for i, role in enumerate(("classifier", "answer"))
        )
        self.serial += 1
        manifest = freeze_manifest(
            attempt_id=attempt["attempt_id"],
            parent_request_id="parent-" + str(self.serial),
            route_sha256=attempt["route"],
            request_sha256=call["request_sha256"],
            expected_call_ids=("classifier", "answer"),
            calls=calls,
        )
        if self.tariff:
            rated_calls = tuple(
                RatedCall(
                    call["call_id"] + "_" + role,
                    i,
                    role,
                    "openai",
                    "fixture",
                    sha({"request": call["request_sha256"], "component": role}),
                    time.time_ns() // 1000000,
                )
                for i, role in enumerate(("classifier", "answer"))
            )
            manifest = RatedManifest(
                attempt["attempt_id"],
                "parent-" + str(self.serial),
                attempt["route"],
                call["request_sha256"],
                tuple(c.call_id for c in rated_calls),
                rated_calls,
            )
        self.manifests[call["call_id"]] = manifest
        return {
            "sse": (
                "".join("data: " + json.dumps(c) + "\n\n" for c in chunks)
                + "data: [DONE]\n\n"
            ).encode(),
            "call_id": call["call_id"],
            "scope_sha256": call["scope_sha256"],
            "request_sha256": call["request_sha256"],
            "physical_manifest_sha256": manifest.sha256(),
        }

    def settle(self, attempt, call, response):
        manifest = self.manifests[call["call_id"]]
        assert response["physical_manifest_sha256"] == manifest.sha256()

        if self.tariff:

            def usage(physical):
                return UsageEvidence(
                    physical.call_id,
                    physical.provider,
                    physical.model,
                    physical.request_sha256,
                    10,
                    0,
                    0,
                    4,
                    0,
                    sha(
                        {
                            "physical": physical.call_id,
                            "synthetic_usage": [10, 0, 0, 4, 0],
                        }
                    ),
                    "complete",
                )

            collector = UsageRatedCollector(self.tariff, self.tariff.sha256(), usage)
            report = collect_usage_for_spending(
                manifest,
                collector=collector,
                authority=self.rpc,
                call_id=call["call_id"],
                scope_sha256=call["scope_sha256"],
                route_sha256=attempt["route"],
                request_sha256=call["request_sha256"],
                expected_components=("classifier", "answer"),
                component_calls={c.role: (c.call_id,) for c in manifest.calls},
                absent_components={},
            )
            self.receipts[call["call_id"]] = report
            return {
                "call_id": call["call_id"],
                "request_sha256": call["request_sha256"],
                "scope_sha256": call["scope_sha256"],
                "route_sha256": attempt["route"],
                "physical_manifest_sha256": manifest.sha256(),
                "billing_receipt_sha256": sha(report),
                "usage_rated_microusd": report["usage_rated_microusd"],
                "usage_rated_usd": report["usage_rated_usd"],
                "tariff_sha256": report["tariff_sha256"],
                "audit_sha256": report["audit_sha256"],
                "source": "synthetic",
                "all_calls_complete": True,
            }

        class SyntheticClient:
            def lookup(self, generation):
                return json.dumps(
                    {
                        "data": {
                            "id": generation,
                            "model": "fixture",
                            "provider_name": "openai",
                            "is_byok": False,
                            "total_cost": "0.000001",
                            "gateway_cost": "0.000001",
                            "usage": "0.000001",
                        }
                    }
                ).encode()

        receipt = collect_for_spending(
            manifest,
            authority=self.rpc,
            client=SyntheticClient(),
            call_id=call["call_id"],
            scope_sha256=call["scope_sha256"],
            route_sha256=attempt["route"],
            request_sha256=call["request_sha256"],
            expected_components=("classifier", "answer"),
            component_calls={"classifier": ("classifier",), "answer": ("answer",)},
            absent_components={},
        )
        self.receipts[call["call_id"]] = receipt
        return {
            "call_id": call["call_id"],
            "scope_sha256": call["scope_sha256"],
            "request_sha256": call["request_sha256"],
            "route_sha256": attempt["route"],
            "physical_manifest_sha256": manifest.sha256(),
            "billing_receipt_sha256": sha(receipt),
            "billed_microusd": receipt["billed_microusd"],
            "source": "synthetic",
            "all_calls_complete": True,
        }

    def close(self, attempt, scope):
        assert scope == self.scopes[attempt["attempt_id"]]
        self.rpc("revoke", self.scopes[attempt["attempt_id"]])


def run(args):
    root = Path(tempfile.mkdtemp(prefix="sfactory-paired-goose-")).resolve()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "RUST_LOG": "info"}
    binary = subprocess.check_output(
        [
            fixture.NODE,
            "-p",
            'require.resolve("@restatedev/restate-server-darwin-arm64/bin/restate-server")',
        ],
        cwd=fixture.PACKAGE,
        text=True,
    ).strip()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    sdk = server = None
    with (
        (root / "sdk.log").open("w") as sdklog,
        (root / "server.log").open("w") as serverlog,
    ):
        try:
            sdk = subprocess.Popen(
                [
                    str(args.sdk),
                    "sdk",
                    f"127.0.0.1:{port}",
                ],
                cwd=root,
                env=env,
                stdout=sdklog,
                stderr=subprocess.STDOUT,
            )
            server = subprocess.Popen(
                [
                    binary,
                    "--base-dir",
                    str(root / "journal"),
                    "--node-name",
                    "paired-goose-fixture",
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
                cwd=root,
                env=env,
                stdout=serverlog,
                stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                ports = {}
                for line in (root / "server.log").read_text().splitlines():
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
                if ports.get("http-ingress-server") and ports.get("admin-api-server"):
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("disposable journal unavailable")
            code, _ = fixture.post(
                f"http://127.0.0.1:{ports['admin-api-server']}/deployments",
                {"uri": f"http://127.0.0.1:{port}"},
            )
            assert code in (200, 201)
            suite = json.loads(
                (ROOT / "crates/execution/harness/frozen-suite.json").read_text()
            )
            config = {
                "benchmark_id": "phase11a-protected-rehearsal",
                "mode": "rehearsal",
                "model": "auto",
                "route": "e" * 64,
                "goose_build": GOOSE_SHA256,
                "profiles": profile_fingerprints(
                    args.goose, args.host, args.normalizer, model="auto", route="e" * 64
                ),
                "budget": 750000,
                "daily_cap": 5000000,
                "budget_owner": "paired-fixture",
            }
            tariff = synthetic_tariff() if args.audited_usage else None
            if tariff:
                config.update(
                    cost_basis="audited_usage_rated", tariff_sha256=tariff.sha256()
                )
            services = RehearsalControl(
                f"http://127.0.0.1:{ports['http-ingress-server']}", suite, tariff
            )
            control = JournaledControl(
                services,
                services.rpc,
                SimpleNamespace(exchange=services.provider_exchange),
                SimpleNamespace(settle=services.settle),
                {
                    "mode": "rehearsal",
                    "owner": config["budget_owner"],
                    "route_sha256": config["route"],
                    "goose_build": GOOSE_SHA256,
                    "profiles": config["profiles"],
                    "model": "auto",
                    "policy_sha256": services.policy_sha,
                    "max_request_bytes": 65536,
                    "max_output_tokens": 16384,
                    "tools": ("read_file", "write_file", "list_files"),
                }
                | (
                    {
                        "cost_basis": "audited_usage_rated",
                        "tariff_sha256": tariff.sha256(),
                    }
                    if tariff
                    else {}
                ),
            )
            adapter = ProtectedGooseAdapter(
                root / "attempts",
                suite,
                goose=args.goose,
                host=args.host,
                normalizer=args.normalizer,
                control=control,
            )
            generate = adapter.generate

            def diagnostic_generate(*values):
                try:
                    return generate(*values)
                except Exception as error:
                    print(
                        json.dumps(
                            {
                                "exception_class": type(error).__name__,
                                "frames": [
                                    (f.name, f.lineno)
                                    for f in traceback.extract_tb(error.__traceback__)
                                ],
                            }
                        ),
                        flush=True,
                    )
                    raise

            adapter.generate = diagnostic_generate
            with Runner(root / "runner", suite, config, create=True) as runner:
                results = [runner.run_next(adapter), runner.run_next(adapter)]
                status = runner.status()
                completed = [
                    v
                    for v in runner.state["records"].values()
                    if v["stage"] == "complete"
                ]
                accepted = sum(v["evaluation"]["accepted"] for v in completed)
                (root / "status.json").write_text(json.dumps(status, indent=2))
                summary = {
                    "synthetic": True,
                    "cost_basis": "audited_usage_rated"
                    if tariff
                    else "provider_billed",
                    "tariff_sha256": tariff.sha256() if tariff else None,
                    "candidate_enabled": False,
                    "completed_live_runs": 0,
                    "root": str(root),
                    "results": results,
                    "status": status,
                    "journal_backed_provider_calls": services.serial,
                    "independently_accepted_rehearsals": accepted,
                    "generation_outcomes": [
                        v["generation"]["outcome"] for v in completed
                    ],
                }
                with args.summary.open("x") as out:
                    json.dump(summary, out, indent=2)
                print(json.dumps(summary, indent=2))
                assert all(r["status"] == "completed" for r in results), (
                    "actual Goose rehearsal failed"
                )
                assert accepted == 2 and all(
                    v["generation"]["outcome"] == "completed" for v in completed
                )
        finally:
            fixture.terminate(server)
            fixture.terminate(sdk)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("goose", "host", "normalizer", "summary"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument(
        "--sdk",
        type=Path,
        default=ROOT / "target/debug/examples/harness_runtime_fixture",
    )
    parser.add_argument("--audited-usage", action="store_true")
    run(parser.parse_args())
