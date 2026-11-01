"""Financial effects must remain behind the sole protected owner journal."""

import copy
import errno
import os
import unittest
from unittest.mock import patch

from protected_spending_control import (
    ControlRefused,
    JournaledControl,
    PrivateSpendingClient,
    _no_acl,
    binding_digest,
)


def fixture(mode="rehearsal"):
    config = {
        "mode": mode,
        "owner": "owner",
        "route_sha256": "a" * 64,
        "goose_build": "b" * 64,
        "profiles": {"baseline": "c" * 64, "candidate": "d" * 64},
        "model": "auto",
        "policy_sha256": "e" * 64,
        "max_request_bytes": 65536,
        "max_output_tokens": 16384,
        "tools": ("read_file", "write_file", "list_files"),
    }
    attempt = {
        "attempt_id": "run_" + "f" * 64,
        "config_sha256": "1" * 64,
        "task_id": "intervals",
        "repeat": 0,
        "variant": "baseline",
        "suite_sha256": "2" * 64,
        "model": "auto",
        "route": "a" * 64,
        "goose_build": "b" * 64,
        "profile": "c" * 64,
        "budget": 750000,
        "daily_cap": 5000000,
        "budget_owner": "owner",
        "mode": mode,
    }
    events = []

    class Launch:
        def admit(self, value):
            events.append("admit")
            from protected_spending_control import binding_digest

            return {
                "status": "allowed",
                "attempt_id": value["attempt_id"],
                "attempt_sha256": binding_digest(value),
                "scope_sha256": "3" * 64,
                "policy_sha256": "e" * 64,
                "owner": "owner",
                "route_sha256": "a" * 64,
                "expires_at_ms": 253402300799000,
                "authority_receipt_sha256": "4" * 64,
            }

        def authorize_tool(self, value, scope, name, args):
            from protected_spending_control import binding_digest

            return {
                "attempt_sha256": binding_digest(value),
                "scope_sha256": scope,
                "name": name,
                "arguments_sha256": args,
                "allowed": True,
            }

        def close(self, value, scope):
            events.append("revoke")

    class Broker:
        reserve = "Reserved"
        begin = True
        failure = None

        def __call__(self, method, call):
            events.append(method)
            if self.failure == method:
                raise RuntimeError("private transport detail")
            return getattr(self, method)

    class Provider:
        def exchange(self, call, body):
            events.append("provider")
            return {
                "sse": b"data: [DONE]\n\n",
                "physical_manifest_sha256": "5" * 64,
                "call_id": call["call_id"],
                "request_sha256": call["request_sha256"],
                "scope_sha256": call["scope_sha256"],
            }

    class Collector:
        fail = False

        def settle(self, value, call, response):
            events.append("collector")
            if self.fail:
                raise RuntimeError("missing classifier receipt")
            return {
                "call_id": call["call_id"],
                "request_sha256": call["request_sha256"],
                "scope_sha256": call["scope_sha256"],
                "route_sha256": "a" * 64,
                "physical_manifest_sha256": response["physical_manifest_sha256"],
                "billing_receipt_sha256": "6" * 64,
                "billed_microusd": 7,
                "source": "synthetic" if mode == "rehearsal" else "provider_billed",
                "all_calls_complete": True,
            }

    launch, broker, provider, collector = Launch(), Broker(), Provider(), Collector()
    control = JournaledControl(launch, broker, provider, collector, config)
    return control, attempt, events, launch, broker, provider, collector


def body():
    return {
        "model": "auto",
        "stream": True,
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "task"}],
        "tools": [],
    }


class ProtectedSpendingControl(unittest.TestCase):
    def test_descriptor_acl_probe_does_not_use_path_symlink_flags(self):
        def getxattr(path, name, **kwargs):
            self.assertEqual(path, 123)
            self.assertEqual(kwargs, {})
            raise OSError(errno.ENODATA, "no ACL")

        with patch("protected_spending_control.os.getxattr", getxattr, create=True):
            _no_acl(123)

    def test_private_broker_transport_cannot_invoke_admin_or_collector(self):
        client = object.__new__(PrivateSpendingClient)
        client.broker_uid = os.geteuid()
        for method in (
            "initialize",
            "admit_attempt",
            "revoke",
            "claim_receipts",
            "complete",
        ):
            with (
                self.subTest(method=method),
                self.assertRaisesRegex(ControlRefused, "role_denied"),
            ):
                client(method, {})

    def test_private_broker_rejects_malformed_types_before_any_connection(self):
        client = object.__new__(PrivateSpendingClient)
        client.broker_uid = os.geteuid()
        call = {
            "call_id": "call",
            "scope_sha256": "a" * 64,
            "request_sha256": "b" * 64,
            "sequence": 0,
            "request_bytes": 1,
            "output_tokens": 1,
        }
        for field, value in (
            ("scope_sha256", "private bad value"),
            ("sequence", True),
            ("output_tokens", -1),
            ("request_bytes", 65537),
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ControlRefused, "invalid_spending_request"),
            ):
                client("reserve", call | {field: value})

    def test_consumed_journal_dispatch_is_not_replayed(self):
        control, attempt, events, _, broker, *_ = fixture()
        control.admit(attempt)
        broker.reserve = "Complete"
        with self.assertRaises(ControlRefused):
            control.exchange(attempt, body(), 0)
        with self.assertRaises(ControlRefused):
            control.exchange(attempt, body(), 0)
        self.assertEqual(events, ["admit", "reserve"])

    def test_malformed_or_unbounded_provider_parameters_never_reach_reservation(self):
        for changed in (
            {"max_tokens": 0},
            {"max_tokens": 16385},
            {"temperature": float("nan")},
            {"max_completion_tokens": 99999},
        ):
            control, attempt, events, *_ = fixture()
            control.admit(attempt)
            with self.subTest(changed=changed), self.assertRaises(ControlRefused):
                control.exchange(attempt, body() | changed, 0)
            self.assertEqual(events, ["admit"])

    def test_wrong_root_grant_cannot_bind_an_attempt(self):
        control, attempt, events, launch, *_ = fixture()
        original = launch.admit
        launch.admit = lambda value: original(value) | {"scope_sha256": "not-a-digest"}
        with self.assertRaisesRegex(ControlRefused, "invalid_launch_receipt"):
            control.admit(attempt)
        with self.assertRaises(ControlRefused):
            control.exchange(attempt, body(), 0)
        self.assertEqual(events, ["admit"])

    def test_complete_receipts_precede_publication_and_aggregate_without_estimates(
        self,
    ):
        control, attempt, events, *_ = fixture()
        admission = control.admit(attempt)
        self.assertEqual(admission["status"], "allowed")
        first = control.exchange(attempt, body(), 0)
        self.assertEqual(first["billed_microusd"], 7)
        second = control.exchange(attempt, body() | {"messages": []}, 1)
        self.assertEqual(
            events,
            [
                "admit",
                "reserve",
                "begin",
                "provider",
                "collector",
                "reserve",
                "begin",
                "provider",
                "collector",
            ],
        )
        records = [
            {
                "call_id": result["call_id"],
                "physical_manifest_sha256": result["physical_manifest_sha256"],
                "billing_receipt_sha256": result["billing_receipt_sha256"],
                "request_sha256": binding_digest(request),
            }
            for result, request in (
                (first, body()),
                (second, body() | {"messages": []}),
            )
        ]
        generation = {
            "attempt_id": attempt["attempt_id"],
            "dispatch_manifest_sha256": binding_digest(records),
            "call_ids": [first["call_id"], second["call_id"]],
        }
        billing = control.billing(attempt, generation)
        self.assertEqual(billing["billed_microusd"], 14)
        self.assertEqual(billing["source"], "synthetic")
        with self.assertRaises(ControlRefused):
            control.billing(
                attempt, generation | {"dispatch_manifest_sha256": "7" * 64}
            )
        self.assertTrue(control.authorize_tool(attempt, "read_file", "8" * 64))
        self.assertFalse(control.authorize_tool(attempt, "shell", "8" * 64))

    def test_current_live_route_denies_before_launch_or_any_inference(self):
        control, attempt, events, *_ = fixture("live")
        receipt = control.admit(attempt)
        self.assertEqual(receipt["status"], "denied")
        self.assertEqual(events, [])
        with self.assertRaises(ControlRefused):
            control.exchange(attempt, body(), 0)
        self.assertEqual(events, [])

    def test_rated_live_route_denies_before_launch_even_with_permissive_metadata(self):
        old, attempt, events, launch, broker, provider, collector = fixture("live")
        tariff = "9" * 64
        launch_admit = launch.admit
        launch.admit = lambda value: launch_admit(value) | {
            "cost_basis": "audited_usage_rated",
            "tariff_sha256": tariff,
        }
        control = JournaledControl(
            launch,
            broker,
            provider,
            collector,
            old.config | {"cost_basis": "audited_usage_rated", "tariff_sha256": tariff},
        )
        attempt |= {"cost_basis": "audited_usage_rated", "tariff_sha256": tariff}
        with patch(
            "protected_spending_control.assess_receipt_sources",
            return_value={"allows_live_inference": True},
        ):
            receipt = control.admit(attempt)
        self.assertEqual(receipt["status"], "denied")
        self.assertEqual(events, [])
        with self.assertRaises(ControlRefused):
            control.exchange(attempt, body(), 0)
        self.assertEqual(events, [])

    def test_unknown_acknowledgements_are_never_automatically_retried(self):
        for failure, expected in (
            ("reserve", ["admit", "reserve"]),
            ("begin", ["admit", "reserve", "begin"]),
        ):
            control, attempt, events, _, broker, *_ = fixture()
            control.admit(attempt)
            broker.failure = failure
            with self.assertRaisesRegex(
                ControlRefused, "dispatch_outcome_unknown"
            ) as error:
                control.exchange(attempt, body(), 0)
            self.assertNotIn("private", str(error.exception))
            self.assertEqual(events, expected)
            with self.assertRaises(ControlRefused):
                control.exchange(attempt, body(), 0)
            self.assertEqual(events, expected)

    def test_incomplete_classifier_billing_never_returns_sse_or_allows_another_send(
        self,
    ):
        control, attempt, events, _, _, _, collector = fixture()
        control.admit(attempt)
        collector.fail = True
        with self.assertRaises(ControlRefused):
            control.exchange(attempt, body(), 0)
        self.assertEqual(events, ["admit", "reserve", "begin", "provider", "collector"])
        with self.assertRaises(ControlRefused):
            control.exchange(attempt, body(), 1)
        self.assertEqual(events.count("provider"), 1)

    def test_changed_grant_configuration_and_sequences_cannot_spend(self):
        for field, value in (
            ("route", "9" * 64),
            ("budget", 750001),
            ("daily_cap", 5000001),
            ("goose_build", "9" * 64),
        ):
            control, attempt, events, *_ = fixture()
            changed = copy.deepcopy(attempt)
            changed[field] = value
            with self.assertRaises(ControlRefused):
                control.admit(changed)
            self.assertEqual(events, [])
        control, attempt, events, *_ = fixture()
        control.admit(attempt)
        with self.assertRaises(ControlRefused):
            control.exchange(attempt, body(), 1)
        self.assertEqual(events, ["admit"])

    def test_collector_scope_and_source_forgery_leaves_dispatch_unknown(self):
        for field, value in (
            ("scope_sha256", "9" * 64),
            ("source", "catalog_estimate"),
            ("all_calls_complete", False),
            ("billed_microusd", True),
        ):
            control, attempt, events, _, _, _, collector = fixture()
            control.admit(attempt)
            original = collector.settle
            collector.settle = lambda *args, field=field, value=value: original(
                *args
            ) | {field: value}
            with self.assertRaises(ControlRefused):
                control.exchange(attempt, body(), 0)
            with self.assertRaises(ControlRefused):
                control.billing(
                    attempt,
                    {
                        "attempt_id": attempt["attempt_id"],
                        "call_ids": [],
                        "dispatch_manifest_sha256": "7" * 64,
                    },
                )


if __name__ == "__main__":
    unittest.main()
