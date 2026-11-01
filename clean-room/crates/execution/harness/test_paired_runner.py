"""Runner protocol fixtures are not live benchmark or provider billing evidence."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paired_runner import Runner, RunnerRefused, schedule


HERE = Path(__file__).resolve().parent
SUITE = json.loads((HERE / "frozen-suite.json").read_text())
CONFIG = {
    "benchmark_id": "phase11a-test",
    "mode": "rehearsal",
    "model": "auto",
    "route": "a" * 64,
    "goose_build": "b" * 64,
    "profiles": {"baseline": "c" * 64, "candidate": "d" * 64},
    "budget": 750000,
    "daily_cap": 5000000,
    "budget_owner": "fixture-owner",
}


class Adapter:
    def __init__(self):
        self.admitted = []
        self.generated = []
        self.day_cap = False
        self.missing_bill = False
        self.bad_generation = False
        self.unsafe = False
        self.records = {}

    def admit(self, attempt):
        self.admitted.append(attempt["attempt_id"])
        return {
            "attempt_id": attempt["attempt_id"],
            "status": "day_cap" if self.day_cap else "allowed",
            "authority_receipt_sha256": "1" * 64,
        }

    def generate(self, attempt, admission):
        self.generated.append(attempt["attempt_id"])
        value = {
            "attempt_id": attempt["attempt_id"],
            "artifact_sha256": "2" * 64,
            "dispatch_manifest_sha256": "3" * 64,
            "call_ids": ["call-" + attempt["attempt_id"]],
            "elapsed_ms": 100,
            "generation_receipt_sha256": "4" * 64,
            "model": attempt["model"],
            "route": attempt["route"],
            "goose_build": attempt["goose_build"],
            "profile": attempt["profile"],
            "outcome": "completed",
            "live": attempt["mode"] == "live",
        }
        if self.bad_generation:
            value["route"] = "e" * 64
        self.records[attempt["attempt_id"]] = value
        return value

    def evaluate(self, attempt, generation):
        return {
            "attempt_id": attempt["attempt_id"],
            "artifact_sha256": generation["artifact_sha256"],
            "accepted": True,
            "independent": True,
            "safety_passed": not self.unsafe,
            "evaluation_receipt_sha256": "5" * 64,
            "evaluator_build": "6" * 64,
        }

    def collect(self, attempt, generation):
        return {
            "attempt_id": attempt["attempt_id"],
            "dispatch_manifest_sha256": generation["dispatch_manifest_sha256"],
            "call_ids": generation["call_ids"],
            "billed_microusd": None
            if self.missing_bill
            else (1000 if attempt["variant"] == "baseline" else 800),
            "receipt_sha256": "7" * 64,
            "source": "provider_billed" if attempt["mode"] == "live" else "synthetic",
            "all_calls_complete": True,
        }

    def reconcile(self, attempt, record):
        generation = self.records[attempt["attempt_id"]]
        return {
            "attempt_id": attempt["attempt_id"],
            "status": "complete",
            "admission": self.admit(attempt),
            "generation": generation,
            "evaluation": self.evaluate(attempt, generation),
            "billing": self.collect(attempt, generation),
            "reconciliation_receipt_sha256": "8" * 64,
        }


class PairedRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "ledger"

    def tearDown(self):
        self.tmp.cleanup()

    def test_schedule_is_balanced_bound_120_and_rehearsal_cannot_pass(self):
        attempts = schedule(SUITE, CONFIG)
        self.assertEqual(len(attempts), 120)
        self.assertEqual(len({a["attempt_id"] for a in attempts}), 120)
        self.assertEqual(sum(a["variant"] == "baseline" for a in attempts), 60)
        for a, b in zip(attempts[::2], attempts[1::2]):
            self.assertEqual((a["task_id"], a["repeat"]), (b["task_id"], b["repeat"]))
            self.assertNotEqual(a["variant"], b["variant"])
            self.assertEqual(a["route"], b["route"])
        adapter = Adapter()
        with Runner(self.root, SUITE, CONFIG, create=True) as runner:
            report = runner.run(adapter)
            self.assertEqual(report["status"], "finished")
            status = runner.status()
            self.assertEqual(status["completed_runs"], 120)
            self.assertEqual(status["completed_live_runs"], 0)
            self.assertFalse(status["performance_gate"]["passed"])
            self.assertEqual(status["performance_gate"]["reason"], "synthetic_evidence")
            self.assertFalse(status["candidate_enabled"])
        data = (self.root / "ledger.json").read_text()
        self.assertNotIn(SUITE["tasks"][0]["spec"], data)
        self.assertEqual((self.root / "ledger.json").stat().st_mode & 0o777, 0o600)

    def test_day_cap_resume_same_attempt_without_duplicate_or_budget_reset(self):
        adapter = Adapter()
        adapter.day_cap = True
        with Runner(self.root, SUITE, CONFIG, create=True) as runner:
            first = runner.run_next(adapter)
            self.assertEqual(first["status"], "day_cap")
            self.assertEqual(runner.status()["completed_runs"], 0)
            self.assertEqual(adapter.generated, [])
        adapter.day_cap = False
        with Runner(self.root, SUITE, CONFIG) as runner:
            second = runner.run_next(adapter)
            self.assertEqual(second["attempt_id"], first["attempt_id"])
            self.assertEqual(second["status"], "completed")
            runner.run_next(adapter)
        self.assertEqual(len(adapter.generated), len(set(adapter.generated)))

    def test_generator_crash_is_retained_and_never_automatically_dispatched_again(self):
        class Crashed(Adapter):
            def generate(self, attempt, admission):
                super().generate(attempt, admission)
                raise KeyboardInterrupt("simulated process interruption")

        adapter = Crashed()
        with Runner(self.root, SUITE, CONFIG, create=True) as runner:
            with self.assertRaises(KeyboardInterrupt):
                runner.run_next(adapter)
        with Runner(self.root, SUITE, CONFIG) as runner:
            self.assertEqual(
                runner.run_next(adapter)["status"], "reconciliation_required"
            )
            self.assertEqual(runner.status()["completed_runs"], 0)
            self.assertEqual(len(adapter.generated), 1)

    def test_independent_evaluator_build_cannot_change_between_attempts(self):
        class Changed(Adapter):
            def evaluate(self, attempt, generation):
                value = super().evaluate(attempt, generation)
                if len(self.generated) > 1:
                    value["evaluator_build"] = "9" * 64
                return value

        adapter = Changed()
        with Runner(self.root, SUITE, CONFIG, create=True) as runner:
            self.assertEqual(runner.run_next(adapter)["status"], "completed")
            self.assertEqual(
                runner.run_next(adapter)["status"], "reconciliation_required"
            )
            self.assertEqual(runner.status()["completed_runs"], 1)

    def test_safety_failure_stops_before_another_attempt(self):
        adapter = Adapter()
        adapter.unsafe = True
        with Runner(self.root, SUITE, CONFIG, create=True) as runner:
            self.assertEqual(runner.run(adapter)["status"], "safety_regression")
            self.assertEqual(runner.run_next(adapter)["status"], "safety_regression")
            self.assertEqual(len(adapter.generated), 1)
        adapter = Adapter()
        adapter.unsafe = adapter.missing_bill = True
        with Runner(
            self.root.with_name("unsafe-reconcile"), SUITE, CONFIG, create=True
        ) as runner:
            report = runner.run_next(adapter)
            adapter.missing_bill = False
            self.assertEqual(
                runner.reconcile(adapter, report["attempt_id"])["status"],
                "safety_regression",
            )

    def test_accepted_task_regression_fails_frozen_live_gate(self):
        class Regression(Adapter):
            def evaluate(self, attempt, generation):
                value = super().evaluate(attempt, generation)
                value["accepted"] = attempt["variant"] == "baseline"
                return value

        config = CONFIG | {"mode": "live"}
        with Runner(self.root, SUITE, config, create=True) as runner:
            runner.run(Regression())
            gate = runner.status()["performance_gate"]
            self.assertEqual(gate["reason"], "acceptance_regression")
            self.assertFalse(gate["passed"])

    def test_invalid_generation_blocks_resume_until_explicit_trusted_reconciliation(
        self,
    ):
        adapter = Adapter()
        adapter.bad_generation = True
        with Runner(self.root, SUITE, CONFIG, create=True) as runner:
            report = runner.run_next(adapter)
            self.assertEqual(report["status"], "reconciliation_required")
            attempt_id = report["attempt_id"]
        with Runner(self.root, SUITE, CONFIG) as runner:
            self.assertEqual(
                runner.run_next(adapter)["status"], "reconciliation_required"
            )
            self.assertEqual(len(adapter.generated), 1)
            adapter.records[attempt_id]["route"] = CONFIG["route"]
            adapter.bad_generation = False
            self.assertEqual(
                runner.reconcile(adapter, attempt_id)["status"], "completed"
            )
            self.assertEqual(len(adapter.generated), 1)

    def test_incomplete_billing_retains_generated_work_and_does_not_count_run(self):
        adapter = Adapter()
        adapter.missing_bill = True
        with Runner(self.root, SUITE, CONFIG, create=True) as runner:
            report = runner.run_next(adapter)
            self.assertEqual(report["status"], "reconciliation_required")
            self.assertEqual(runner.status()["completed_runs"], 0)
            self.assertEqual(runner.run_next(adapter), report)
            self.assertEqual(len(adapter.generated), 1)
            adapter.missing_bill = False
            self.assertEqual(
                runner.reconcile(adapter, report["attempt_id"])["status"], "completed"
            )
            self.assertEqual(len(adapter.generated), 1)

    def test_provenance_ledger_tampering_lock_and_explicit_initialization_refuse(self):
        with self.assertRaises(RunnerRefused):
            Runner(self.root, SUITE, CONFIG)
        with Runner(self.root, SUITE, CONFIG, create=True):
            with self.assertRaises(RunnerRefused):
                Runner(self.root, SUITE, CONFIG)
        changed = CONFIG | {"route": "f" * 64}
        with self.assertRaises(RunnerRefused):
            Runner(self.root, SUITE, changed)
        with self.assertRaises(RunnerRefused):
            Runner(self.root, SUITE, CONFIG, create=True)
        path = self.root / "ledger.json"
        raw = json.loads(path.read_text())
        raw["records"][next(iter(raw["records"]))]["stage"] = "complete"
        path.write_text(json.dumps(raw))
        with self.assertRaises(RunnerRefused):
            Runner(self.root, SUITE, CONFIG)

    def test_ledger_write_failure_before_dispatch_never_calls_adapter(self):
        adapter = Adapter()
        with Runner(self.root, SUITE, CONFIG, create=True) as runner:
            with patch.object(
                runner, "_persist", side_effect=OSError("private-secret")
            ):
                with self.assertRaises(RunnerRefused) as caught:
                    runner.run_next(adapter)
            self.assertNotIn("private-secret", str(caught.exception))
            self.assertEqual(adapter.generated, [])
            self.assertEqual(adapter.admitted, [])

    def test_live_gate_uses_actual_complete_rows_but_does_not_enable(self):
        config = CONFIG | {"mode": "live"}
        with Runner(self.root, SUITE, config, create=True) as runner:
            runner.run(Adapter())
            status = runner.status()
            self.assertEqual(status["completed_live_runs"], 120)
            self.assertTrue(status["performance_gate"]["passed"])
            self.assertFalse(status["candidate_enabled"])
        # These are protocol unit fixtures claiming live provenance, not actual
        # paid attempts or independently attested provider receipts.


if __name__ == "__main__":
    unittest.main()
