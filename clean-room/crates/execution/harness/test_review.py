"""Regression controls for the independent Phase 11A review findings."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

from factory_harness import Broker, Profile, Tool, run_script
from harness_evaluation import evaluate, freeze_suite, workspace_hash
from harness_session import CandidateSession


class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.host = Path(os.environ["SFACTORY_TEST_SCRIPT_HOST"])
        self.normalizer = Path(os.environ["SFACTORY_TEST_NORMALIZER"])

    def normalize(self, text):
        value = subprocess.run(
            [str(self.normalizer)], input=text.encode(), capture_output=True, check=True
        )
        return json.loads(value.stdout)["text"]

    def broker(self, normalize=None, invoke=lambda _: "done"):
        return Broker(
            Profile(
                "v1",
                "g",
                "m",
                "r",
                "static",
                [
                    Tool("read", "Read", {}, True, invoke),
                    Tool("mutate", "Write", {}, False, invoke),
                ],
            ),
            lambda *_: True,
            normalize or self.normalize,
        )

    def session(self, root, broker=None):
        return CandidateSession(
            host=self.host,
            broker=broker or self.broker(),
            artifact_root=Path(root),
            attempt="a",
            snapshot=lambda: "same",
            deadline=time.monotonic() + 10,
            cancelled=threading.Event(),
        )

    def test_deep_rpc_and_invalid_unicode_are_typed_refusals(self):
        for script in [
            'let x={};for(let i=0;i<1100;i++)x={x};return await tools.call("read",x);',
            "\ud800",
        ]:
            self.assertEqual(
                run_script(self.host, script, self.broker())["status"], "refused"
            )

    def test_normalizer_failures_and_wrong_types_withhold_output(self):
        def broken(_):
            raise subprocess.CalledProcessError(1, ["normalizer"])

        for normalize in [broken, lambda _: None]:
            result = run_script(self.host, 'return "private";', self.broker(normalize))
            self.assertEqual(result["status"], "refused")
            self.assertNotIn("output", result)

    def test_deleted_tracked_directory_and_rename_hash_without_host_reads(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subprocess.run(["git", "init", "-q", td], check=True)
            (root / "nested").mkdir()
            (root / "nested/file").write_text("file")
            subprocess.run(["git", "-C", td, "add", "nested/file"], check=True)
            original = workspace_hash(root)
            (root / "nested").rename(root / "renamed")
            renamed = workspace_hash(root)
            self.assertNotEqual(original, renamed)
            shutil.rmtree(root / "renamed")
            self.assertNotEqual(renamed, workspace_hash(root))

    def test_concurrent_session_call_is_busy_before_mutation(self):
        entered = threading.Event()
        release = threading.Event()
        invoked = []

        def invoke(args):
            invoked.append(args)
            entered.set()
            release.wait(timeout=2)
            return "done"

        with tempfile.TemporaryDirectory() as td:
            s = self.session(td, self.broker(invoke=invoke))
            first = []
            thread = threading.Thread(
                target=lambda: first.append(
                    s.call(
                        "run_script",
                        {"script": 'return await tools.call("mutate",{i:1});'},
                    )
                )
            )
            thread.start()
            self.assertTrue(entered.wait(timeout=2))
            second = s.call(
                "run_script", {"script": 'return await tools.call("mutate",{i:2});'}
            )
            release.set()
            thread.join(timeout=3)
            self.assertEqual(second, {"status": "refused", "reason": "busy"})
            self.assertEqual(invoked, [{"i": 1}])
            self.assertEqual(first[0]["status"], "executed")

    def test_artifact_quota_and_storage_errors_return_no_output_or_handle(self):
        with tempfile.TemporaryDirectory() as td:
            s = self.session(td)
            s.artifacts.limit = 1
            value = s.call("run_script", {"script": 'return "longer";'})
            self.assertEqual(
                value, {"status": "refused", "reason": "artifact_unavailable"}
            )
        with tempfile.TemporaryDirectory() as td:
            s = self.session(td)

            def failed(_):
                raise OSError("private path")

            s.artifacts.put = failed
            self.assertEqual(
                s.call("run_script", {"script": 'return "private";'}),
                {"status": "refused", "reason": "artifact_unavailable"},
            )

    def test_distinct_errors_do_not_false_stall_but_repeat_does(self):
        with tempfile.TemporaryDirectory() as td:
            s = self.session(td)
            for name in ["first_missing", "second_missing", "third_missing"]:
                value = s.call("run_script", {"script": f"return {name};"})
                self.assertEqual(value["status"], "refused")
                self.assertNotIn(name, json.dumps(value))
            self.assertEqual(
                s.call("run_script", {"script": "return third_missing;"})["status"],
                "refused",
            )
            self.assertEqual(
                s.call("run_script", {"script": "return third_missing;"})["status"],
                "intervention",
            )

    def test_prefix_indexes_names_and_teaches_bridge_without_full_schemas(self):
        profile = self.broker().profile
        prefix = profile.prefix()
        parsed = json.loads(prefix)
        self.assertEqual(parsed["available_tools"], ["mutate", "read"])
        self.assertIn("tools.call", parsed["script_api"])
        self.assertNotIn("inputSchema", prefix)
        profile.instructions = "dynamic contamination"
        self.assertEqual(profile.prefix(), prefix)

    def test_finite_allocations_prove_heap_cap_independently_of_timeout(self):
        below = run_script(
            self.host,
            'return "x".repeat(8*1024*1024).length;',
            self.broker(),
            timeout=5,
        )
        self.assertEqual(below["status"], "executed")
        self.assertEqual(json.loads(below["output"]), 8 * 1024 * 1024)
        above = run_script(
            self.host,
            'return "x".repeat(40*1024*1024).length;',
            self.broker(),
            timeout=5,
        )
        self.assertEqual(above["status"], "refused")
        self.assertNotEqual(above["reason"], "timed_out")

    def test_failed_attempts_remain_in_cost_per_accepted_task(self):
        suite = freeze_suite([{"id": str(i), "spec": f"Build {i}"} for i in range(20)])
        rows = []
        for task in suite["tasks"]:
            for repeat in range(3):
                for variant in ("baseline", "candidate"):
                    cost = (
                        100 if variant == "baseline" else (90 if repeat < 2 else 1000)
                    )
                    rows.append(
                        dict(
                            task_id=task["id"],
                            repeat=repeat,
                            variant=variant,
                            suite_sha256=suite["sha256"],
                            goose_build="g",
                            profile=variant,
                            model="m",
                            route="r",
                            budget=1000,
                            accepted=repeat < 2,
                            independent=True,
                            safety_passed=True,
                            billed_microusd=cost,
                            elapsed_ms=100,
                        )
                    )
        result = evaluate(suite, rows)
        self.assertFalse(result["passed"])
        self.assertEqual(result["reason"], "performance_gate")
        self.assertEqual(
            result["median_cost_per_accepted_task_microusd"],
            {"baseline": 150, "candidate": 590},
        )


if __name__ == "__main__":
    unittest.main()
