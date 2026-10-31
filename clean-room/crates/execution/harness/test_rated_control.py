"""Audited usage changes metrics, never supplies a production launch grant."""

import unittest
from protected_spending_control import JournaledControl, ControlRefused, binding_digest
from test_protected_spending_control import fixture, body

CARD = "9" * 64


def rated_fixture(mode="rehearsal"):
    old, attempt, events, launch, broker, provider, collector = fixture(mode)
    config = old.config | {"cost_basis": "audited_usage_rated", "tariff_sha256": CARD}
    attempt = attempt | {"cost_basis": "audited_usage_rated", "tariff_sha256": CARD}
    old_admit, old_settle = launch.admit, collector.settle
    launch.admit = lambda value: old_admit(value) | {
        "cost_basis": "audited_usage_rated",
        "tariff_sha256": CARD,
    }

    def settle(value, call, response):
        result = old_settle(value, call, response)
        del result["billed_microusd"]
        return result | {
            "usage_rated_microusd": 1,
            "usage_rated_usd": "0.0000004",
            "tariff_sha256": CARD,
            "audit_sha256": "8" * 64,
        }

    collector.settle = settle
    return (
        JournaledControl(launch, broker, provider, collector, config),
        attempt,
        events,
        launch,
        collector,
    )


class RatedControl(unittest.TestCase):
    def test_rated_closure_precedes_publication_and_rounds_once_per_attempt(self):
        control, attempt, events, *_ = rated_fixture()
        control.admit(attempt)
        records = []
        for sequence in range(2):
            result = control.exchange(attempt, body(), sequence)
            self.assertEqual(result["usage_rated_microusd"], 1)
            self.assertNotIn("billed_microusd", result)
            records.append(
                {
                    k: result[k]
                    for k in (
                        "call_id",
                        "physical_manifest_sha256",
                        "billing_receipt_sha256",
                    )
                }
                | {"request_sha256": binding_digest(body())}
            )
        control.revoke(attempt)
        generation = {
            "attempt_id": attempt["attempt_id"],
            "dispatch_manifest_sha256": binding_digest(records),
            "call_ids": [r["call_id"] for r in records],
        }
        result = control.billing(attempt, generation)
        self.assertEqual(result["usage_rated_microusd"], 1)
        self.assertNotIn("billed_microusd", result)
        self.assertEqual(result["tariff_sha256"], CARD)
        self.assertEqual(result["source"], "synthetic")
        self.assertEqual(len(result["audit_sha256"]), 64)
        self.assertEqual(events.count("provider"), 2)

    def test_bad_usage_receipt_stays_unknown_without_resend(self):
        for changes in (
            {"tariff_sha256": "1" * 64},
            {"usage_rated_usd": None},
            {"usage_rated_usd": "0.000002"},
            {"audit_sha256": None},
            {"billed_microusd": 1},
        ):
            control, attempt, events, _, collector = rated_fixture()
            original = collector.settle
            collector.settle = lambda *args: original(*args) | changes
            control.admit(attempt)
            with self.subTest(changes=changes), self.assertRaises(ControlRefused):
                control.exchange(attempt, body(), 0)
            with self.assertRaises(ControlRefused):
                control.exchange(attempt, body(), 0)
            self.assertEqual(events.count("provider"), 1)

    def test_metric_choice_does_not_admit_live_or_change_root_tariff(self):
        control, attempt, events, *_ = rated_fixture("live")
        self.assertEqual(control.admit(attempt)["status"], "denied")
        self.assertEqual(events, [])
        control, attempt, events, launch, _ = rated_fixture()
        original = launch.admit
        launch.admit = lambda value: original(value) | {"tariff_sha256": "1" * 64}
        with self.assertRaises(ControlRefused):
            control.admit(attempt)
        self.assertEqual(events, ["admit"])
