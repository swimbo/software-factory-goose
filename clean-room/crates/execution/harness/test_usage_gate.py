"""Scripted protocol tests never establish live benchmark attempts or authority."""

import copy
import tempfile
import unittest
from pathlib import Path

from harness_evaluation import evaluate
from paired_runner import Runner, RunnerRefused, _billing, schedule
from test_paired_runner import Adapter, CONFIG, SUITE


CARD = "9" * 64


def rated_config():
    return CONFIG | {
        "mode": "live",
        "cost_basis": "audited_usage_rated",
        "tariff_sha256": CARD,
    }


class RatedAdapter(Adapter):
    def collect(self, attempt, generation):
        return {
            "attempt_id": attempt["attempt_id"],
            "dispatch_manifest_sha256": generation["dispatch_manifest_sha256"],
            "call_ids": generation["call_ids"],
            "usage_rated_microusd": 1000 if attempt["variant"] == "baseline" else 800,
            "receipt_sha256": "7" * 64,
            "source": "audited_usage_rated",
            "tariff_sha256": attempt["tariff_sha256"],
            "audit_sha256": "8" * 64,
            "all_calls_complete": True,
        }


class UsageGate(unittest.TestCase):
    def test_scripted_rated_attempts_score_without_becoming_billed_or_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner(Path(d) / "ledger", SUITE, rated_config(), create=True)
            self.addCleanup(runner.close)
            runner.run(RatedAdapter(), max_attempts=120)
            gate = runner.status()["performance_gate"]
            self.assertTrue(gate["passed"])
            self.assertEqual(gate["cost_basis"], "audited_usage_rated")
            self.assertEqual(gate["tariff_sha256"], CARD)
            self.assertFalse(gate["candidate_enabled"])
            for attempt in runner.attempts:
                row = runner._row(
                    attempt, runner.state["records"][attempt["attempt_id"]]
                )
                self.assertIn("usage_rated_microusd", row)
                self.assertNotIn("billed_microusd", row)
            runner.close()
            with Runner(Path(d) / "ledger", SUITE, rated_config()) as reopened:
                self.assertEqual(reopened.status()["completed_runs"], 120)
            changed = rated_config() | {"tariff_sha256": "1" * 64}
            with self.assertRaisesRegex(RunnerRefused, "ledger_binding_mismatch"):
                Runner(Path(d) / "ledger", SUITE, changed)

    def test_rehearsal_status_keeps_its_explicit_rated_basis(self):
        with tempfile.TemporaryDirectory() as d:
            config = rated_config() | {"mode": "rehearsal"}
            runner = Runner(Path(d) / "ledger", SUITE, config, create=True)
            self.addCleanup(runner.close)
            gate = runner.status()["performance_gate"]
            self.assertFalse(gate["passed"])
            self.assertEqual(gate["reason"], "synthetic_evidence")
            self.assertEqual(gate["cost_basis"], "audited_usage_rated")
            self.assertEqual(gate["tariff_sha256"], CARD)

    def test_changed_or_incomplete_rated_evidence_is_refused(self):
        attempt = schedule(SUITE, rated_config())[0]
        adapter = RatedAdapter()
        generation = adapter.generate(attempt, adapter.admit(attempt))
        receipt = adapter.collect(attempt, generation)
        _billing(receipt, attempt, generation)
        for changes in (
            {"tariff_sha256": "1" * 64},
            {"audit_sha256": None},
            {"all_calls_complete": False},
            {"usage_rated_microusd": None},
            {"source": "provider_billed"},
            {"billed_microusd": 800},
        ):
            with self.subTest(changes=changes), self.assertRaises(RunnerRefused):
                _billing(receipt | changes, attempt, generation)

    def test_tariff_and_cost_basis_are_part_of_new_attempt_identity(self):
        rated = schedule(SUITE, rated_config())
        legacy = schedule(SUITE, CONFIG | {"mode": "live"})
        changed = schedule(SUITE, rated_config() | {"tariff_sha256": "1" * 64})
        self.assertNotEqual(rated[0]["attempt_id"], legacy[0]["attempt_id"])
        self.assertNotEqual(rated[0]["attempt_id"], changed[0]["attempt_id"])

    def test_mixed_tariffs_and_unlabeled_costs_cannot_pass_direct_gate(self):
        rows = []
        for a in schedule(SUITE, CONFIG | {"mode": "live"}):
            rows.append(
                {
                    k: a[k]
                    for k in (
                        "task_id",
                        "variant",
                        "repeat",
                        "suite_sha256",
                        "model",
                        "route",
                        "goose_build",
                        "profile",
                        "budget",
                    )
                }
                | {
                    "cost_basis": "audited_usage_rated",
                    "tariff_sha256": CARD,
                    "audit_sha256": "8" * 64,
                    "usage_rated_microusd": 1000 if a["variant"] == "baseline" else 800,
                    "elapsed_ms": 100,
                    "accepted": True,
                    "independent": True,
                    "safety_passed": True,
                }
            )
        self.assertTrue(evaluate(SUITE, rows)["passed"])
        for field, value in (
            ("tariff_sha256", "1" * 64),
            ("cost_basis", "provider_billed"),
            ("audit_sha256", None),
            ("billed_microusd", 800),
        ):
            changed = copy.deepcopy(rows)
            changed[-1][field] = value
            with self.subTest(field=field):
                self.assertFalse(evaluate(SUITE, changed)["passed"])


if __name__ == "__main__":
    unittest.main()
