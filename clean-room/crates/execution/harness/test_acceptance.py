"""Failure controls for candidate interfaces, accounting and runtime lifetime."""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest

from factory_harness import ArtifactStore, Broker, Denied, Profile, Tool, run_script
from harness_evaluation import evaluate, freeze_suite, observation
from harness_session import CandidateSession


class TelemetryAndGate(unittest.TestCase):
    def test_unknown_usage_is_not_zero_and_payload_is_unchanged(self):
        body = {
            "messages": [
                {"role": "system", "content": "static"},
                {"role": "user", "content": "dynamic"},
            ]
        }
        original = copy.deepcopy(body)
        fields = dict(goose_build="g", profile="p", model="m", route="r")
        missing = observation(body, None, **fields)
        for name in (
            "prompt_tokens",
            "completion_tokens",
            "cached_tokens",
            "billed_microusd",
            "accepted",
        ):
            self.assertIsNone(missing[name])
        measured = observation(
            body,
            {
                "prompt_tokens": 200,
                "completion_tokens": 10,
                "prompt_tokens_details": {"cached_tokens": 100},
            },
            **fields,
        )
        self.assertEqual(measured["cached_tokens"], 100)
        self.assertEqual(body, original)
        self.assertNotIn("dynamic", json.dumps(measured))

    def test_duplicate_mismatched_unsafe_slow_or_expensive_receipts_cannot_pass(self):
        suite = freeze_suite([{"id": str(i), "spec": f"Build {i}"} for i in range(20)])
        rows = [
            dict(
                task_id=t["id"],
                repeat=n,
                variant=v,
                suite_sha256=suite["sha256"],
                goose_build="g",
                profile=v,
                model="m",
                route="r",
                budget=1000,
                accepted=True,
                independent=True,
                safety_passed=True,
                billed_microusd=100 if v == "baseline" else 90,
                elapsed_ms=100,
            )
            for t in suite["tasks"]
            for n in range(3)
            for v in ("baseline", "candidate")
        ]
        self.assertTrue(evaluate(suite, rows)["passed"])
        for field, value in [
            ("safety_passed", False),
            ("independent", False),
            ("route", "other"),
            ("billed_microusd", True),
            ("goose_build", ""),
            ("repeat", True),
        ]:
            bad = copy.deepcopy(rows)
            bad[-1][field] = value
            self.assertFalse(evaluate(suite, bad)["passed"], field)
        bad = copy.deepcopy(rows)
        bad[-1] = bad[0]
        self.assertFalse(evaluate(suite, bad)["passed"])
        for field, value in [("billed_microusd", 91), ("elapsed_ms", 111)]:
            bad = copy.deepcopy(rows)
            for row in bad:
                if row["variant"] == "candidate":
                    row[field] = value
            self.assertFalse(evaluate(suite, bad)["passed"], field)


class RealRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = Path(os.environ["SFACTORY_TEST_SCRIPT_HOST"])
        cls.normalizer = Path(os.environ["SFACTORY_TEST_NORMALIZER"])
        assert cls.host.is_file() and cls.normalizer.is_file()

    def normalize(self, text):
        p = subprocess.run(
            [str(self.normalizer)], input=text.encode(), capture_output=True, check=True
        )
        return json.loads(p.stdout)["text"]

    def make_broker(self, authority=lambda *_: True, invoke=lambda _: "value"):
        profile = Profile(
            "v1",
            "goose-build",
            "route-model",
            "route-snapshot",
            "static",
            [
                Tool("read", "Read fixture", {"type": "object"}, True, invoke),
                Tool("mutate", "Mutate fixture", {"type": "object"}, False, invoke),
            ],
        )
        return Broker(profile, authority, self.normalize)

    def test_exact_escape_failures_and_no_host_apis(self):
        no_api = run_script(
            self.host,
            "return [typeof std, typeof os, typeof process, typeof fetch, typeof __rpc];",
            self.make_broker(),
        )
        self.assertEqual(no_api["status"], "executed")
        self.assertEqual(json.loads(no_api["output"]), ["undefined"] * 5)
        for code in [
            'return await import("std");',
            'return await import("os");',
            'return await import("/etc/passwd");',
        ]:
            self.assertEqual(
                run_script(self.host, code, self.make_broker())["status"], "refused"
            )

    def test_budget_and_call_count_stop_before_next_mutation(self):
        invoked = []
        b = self.make_broker(
            lambda *_: len(invoked) < 2, lambda a: invoked.append(a) or "done"
        )
        result = run_script(
            self.host, 'for(let i=0;i<4;i++) await tools.call("mutate",{i});', b
        )
        self.assertEqual(result["status"], "refused")
        self.assertEqual(invoked, [{"i": 0}, {"i": 1}])
        b = self.make_broker()
        result = run_script(
            self.host,
            'for(let i=0;i<70;i++) await tools.call("read",{});',
            b,
            timeout=10,
        )
        self.assertEqual(result["status"], "refused")
        self.assertEqual(b.calls, 64)

    def test_whole_batch_is_validated_and_mutations_stay_ordered(self):
        invoked = []
        b = self.make_broker(invoke=lambda a: invoked.append(a) or "done")
        result = run_script(
            self.host,
            'return await tools.readBatch([{name:"read",arguments:{}},{name:"mutate",arguments:{}}]);',
            b,
        )
        self.assertEqual(result["status"], "refused")
        self.assertEqual(invoked, [])
        result = run_script(
            self.host,
            'await tools.call("mutate",{i:1}); await tools.call("mutate",{i:2});',
            b,
        )
        self.assertEqual(result["status"], "executed")
        self.assertEqual(invoked, [{"i": 1}, {"i": 2}])

    def test_complete_output_masking_and_artifact_isolation(self):
        with tempfile.TemporaryDirectory() as td:
            session = CandidateSession(
                host=self.host,
                broker=self.make_broker(),
                artifact_root=Path(td),
                attempt="a",
                snapshot=lambda: "same",
                deadline=time.monotonic() + 10,
                cancelled=threading.Event(),
            )
            result = session.call(
                "run_script",
                {
                    "script": 'console.log("sk-OFFLINE012345"); console.log("6789ABCDEFGHIJKLMN"); return "ok";'
                },
            )
            self.assertEqual(result["status"], "executed")
            self.assertNotIn("sk-OFFLINE", result["output"])
            self.assertIn("[REDACTED]", session.page("a", result["artifact"]))
            with self.assertRaises(Denied):
                session.page("b", result["artifact"])
            self.assertEqual(
                [t["name"] for t in session.declarations()],
                ["run_script", "fetch_tool_schema"],
            )
            self.assertEqual(
                session.call("fetch_tool_schema", {"name": "read"})["status"],
                "executed",
            )

    def test_artifact_symlink_substitution_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(Path(td), "a", self.normalize)
            ref = store.put("safe")
            path = Path(td, ref + ".txt")
            path.unlink()
            path.symlink_to("/etc/passwd")
            with self.assertRaises((Denied, OSError)):
                store.page("a", ref, 0, 20)

    def test_timeout_and_active_cancellation_reap_host(self):
        start = time.monotonic()
        result = run_script(self.host, "while(true){}", self.make_broker(), timeout=0.1)
        self.assertEqual(result["reason"], "timed_out")
        self.assertLess(time.monotonic() - start, 2)
        event = threading.Event()
        timer = threading.Timer(0.1, event.set)
        timer.start()
        try:
            result = run_script(
                self.host,
                "while(true){}",
                self.make_broker(),
                timeout=5,
                cancelled=event,
            )
            self.assertEqual(result["reason"], "cancelled")
        finally:
            timer.join()

    def test_session_intervention_then_typed_stall(self):
        with tempfile.TemporaryDirectory() as td:
            session = CandidateSession(
                host=self.host,
                broker=self.make_broker(lambda *_: False),
                artifact_root=Path(td),
                attempt="a",
                snapshot=lambda: "same",
                deadline=time.monotonic() + 10,
                cancelled=threading.Event(),
            )
            args = {"script": 'return await tools.call("read",{});'}
            for _ in range(2):
                self.assertEqual(session.call("run_script", args)["status"], "refused")
            self.assertEqual(session.call("run_script", args)["status"], "intervention")
            self.assertEqual(
                session.call("run_script", {"script": 'return "diagnostic";'})[
                    "status"
                ],
                "stalled",
            )
            self.assertEqual(
                session.call("run_script", {"script": 'return "later";'})["status"],
                "stalled",
            )


if __name__ == "__main__":
    unittest.main()
