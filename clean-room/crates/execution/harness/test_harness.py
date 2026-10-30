"""Contract tests for the disabled Phase 11A candidate; no inference or activation."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

from factory_harness import (
    ArtifactStore,
    Broker,
    Denied,
    Profile,
    StallDetector,
    Tool,
    run_script,
)
from harness_evaluation import evaluate, freeze_suite, workspace_hash


class Contracts(unittest.TestCase):
    def test_prefix_disclosure_and_authorization_are_separate(self):
        tools = [
            Tool("z", "Last", {"type": "object"}, False, lambda x: "z"),
            Tool("a", "First", {"type": "object"}, True, lambda x: "a"),
        ]
        p = Profile("v1", "build", "model", "route", "Static instructions", tools)
        self.assertEqual(
            p.prefix(),
            Profile(
                "v1", "build", "model", "route", "Static instructions", tools[::-1]
            ).prefix(),
        )
        self.assertNotIn("Last", p.prefix())
        self.assertIn("Last", p.discover("z"))
        with self.assertRaises(Denied):
            Broker(p, lambda *_: False, lambda s: s).call("z", {})

    def test_stalls_allow_one_diagnostic_and_reads_do_not_trigger(self):
        d = StallDetector()
        for _ in range(8):
            self.assertEqual(d.observe("a", None, False), "continue")
        for _ in range(2):
            self.assertEqual(d.observe("a", "error", False), "continue")
        self.assertEqual(d.observe("a", "error", False), "intervene")
        self.assertEqual(d.observe("a", None, False), "stalled")
        self.assertEqual(d.observe("b", None, True), "stalled")
        d = StallDetector()
        for state in ["a", "b", "a", "b"]:
            self.assertEqual(d.observe(state, None, True), "continue")
        self.assertEqual(d.observe("a", None, True), "intervene")

    def test_untracked_content_changes_workspace_fingerprint(self):
        with tempfile.TemporaryDirectory() as td:
            subprocess.run(["git", "init", "-q", td], check=True)
            p = Path(td, "new.txt")
            p.write_text("one")
            before = workspace_hash(Path(td))
            p.write_text("two")
            self.assertNotEqual(before, workspace_hash(Path(td)))

    def test_artifact_scope_masking_pages_and_overflow(self):
        with tempfile.TemporaryDirectory() as td:
            s = ArtifactStore(
                Path(td), "attempt-a", lambda x: x.replace("secret", "[REDACTED]"), 64
            )
            ref = s.put("secret tail")
            self.assertEqual(s.page("attempt-a", ref, 0, 64), "[REDACTED] tail")
            with self.assertRaises(Denied):
                s.page("attempt-b", ref, 0, 64)
            with self.assertRaises(Denied):
                s.page("attempt-a", "../x", 0, 64)
            with self.assertRaises(Denied):
                s.put("x" * 65)
            self.assertNotIn(
                "secret", "".join(p.read_text() for p in Path(td).rglob("*.txt"))
            )

    def test_paired_gate_rejects_missing_data_and_regressions(self):
        suite = freeze_suite(
            [{"id": str(i), "spec": "Build %s" % i} for i in range(20)]
        )
        rows = []
        for task in suite["tasks"]:
            for repeat in range(3):
                for variant, cost in [("baseline", 100), ("candidate", 85)]:
                    rows.append(
                        dict(
                            task_id=task["id"],
                            repeat=repeat,
                            variant=variant,
                            suite_sha256=suite["sha256"],
                            model="model",
                            route="route",
                            budget=1000,
                            goose_build="build",
                            profile=variant,
                            accepted=True,
                            independent=True,
                            safety_passed=True,
                            billed_microusd=cost,
                            elapsed_ms=100,
                        )
                    )
        self.assertTrue(evaluate(suite, rows)["passed"])
        self.assertFalse(evaluate(suite, rows[:-1])["passed"])
        rows[-1]["billed_microusd"] = None
        self.assertFalse(evaluate(suite, rows)["passed"])
        rows[-1]["billed_microusd"] = 85
        rows[-1]["accepted"] = False
        self.assertFalse(evaluate(suite, rows)["passed"])


class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = Path(os.environ["SFACTORY_TEST_SCRIPT_HOST"])
        cls.normalizer = Path(os.environ["SFACTORY_TEST_NORMALIZER"])
        assert cls.host.is_file() and cls.normalizer.is_file(), (
            "Build real host and normalizer first"
        )

    def normalize(self, text):
        p = subprocess.run(
            [str(self.normalizer)], input=text.encode(), capture_output=True, check=True
        )
        return json.loads(p.stdout)["text"]

    def broker(self, allowed=lambda *_: True):
        p = Profile(
            "v1",
            "build",
            "model",
            "route",
            "static",
            [
                Tool(
                    "read",
                    "Read fixture",
                    {"type": "object"},
                    True,
                    lambda a: "alpha beta",
                ),
                Tool(
                    "write",
                    "Write fixture",
                    {"type": "object"},
                    False,
                    lambda a: "written",
                ),
            ],
        )
        return Broker(p, allowed, self.normalize)

    def test_real_js_batch_and_safe_output(self):
        b = self.broker()
        result = run_script(
            self.host,
            'const xs = await tools.readBatch([{name:"read",arguments:{}}]); console.log("sk-OFFLINE0123456789ABCDEFGHIJKLMN"); return xs[0].split(" ")[0];',
            b,
        )
        self.assertEqual(result["status"], "executed")
        self.assertNotIn("sk-OFFLINE", result["output"])
        self.assertIn("alpha", result["output"])

    def test_escape_limits_denials_and_cancellation(self):
        for script in [
            "return typeof std + typeof os + typeof process + typeof fetch;",
            'return await import("std");',
            'return Function("return typeof process")();',
        ]:
            result = run_script(self.host, script, self.broker())
            self.assertNotIn("object", result.get("output", ""))
        for script in [
            "while(true){}",
            'let x=[]; while(true){x.push("x".repeat(1000000))}',
            'console.log("x".repeat(20000));',
            'return await tools.call("read",{});',
        ]:
            self.assertEqual(
                run_script(
                    self.host, script, self.broker(lambda *_: False), timeout=0.2
                )["status"],
                "refused",
            )
        cancel = threading.Event()
        cancel.set()
        self.assertEqual(
            run_script(self.host, "return 1;", self.broker(), cancelled=cancel)[
                "reason"
            ],
            "cancelled",
        )
        self.assertEqual(
            run_script(
                self.host,
                'return tools.readBatch([{name:"write",arguments:{}}]);',
                self.broker(),
            )["status"],
            "refused",
        )


if __name__ == "__main__":
    unittest.main()
