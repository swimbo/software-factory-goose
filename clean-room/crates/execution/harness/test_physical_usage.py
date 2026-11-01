"""Pure conversion and authenticated-client seams, never a live admission proof."""

import copy
from dataclasses import replace
import os
import json
import unittest

from physical_usage import (
    CaptureBinding,
    UsageSchemaProfile,
    PrivateCaptureClient,
    PrivateCollectorClient,
    PhysicalUsageCollector,
    normalize_capture,
    payload_sha256,
)
from protected_spending_control import ControlRefused
from usage_rating import TariffCard, TariffRate, UsageRatedCollector, UsageRatingRefused

H = "a" * 64


def fixture():
    binding = CaptureBinding(
        1, "owner", "run_" + H, "logical", "b" * 64, "c" * 64, "d" * 64, "e" * 64, ""
    )
    profile = UsageSchemaProfile(
        "chat-v1",
        "provider",
        "model",
        ("answer",),
        H,
        "usage.prompt_tokens",
        "usage.completion_tokens",
        "inclusive_output_total",
        "usage.prompt_tokens_details.cached_tokens",
        None,
        "usage.completion_tokens_details.reasoning_tokens",
    )
    payload = {
        "snapshot": {
            "root_id": "logical",
            "sealed": True,
            "complete": True,
            "calls": [
                {
                    "sequence": 0,
                    "permit_id": "physical",
                    "request_sha256": "f" * 64,
                    "role": "answer",
                    "provider": "provider",
                    "model": "model",
                    "started_at": 20,
                    "status_code": 200,
                    "state": "complete",
                    "usage": {
                        "usage.prompt_tokens": 10,
                        "usage.completion_tokens": 4,
                        "usage.prompt_tokens_details.cached_tokens": 2,
                    },
                    "trace_sha256": H,
                }
            ],
        },
        "component_calls": {"answer": ["physical"]},
        "absent_components": {"fallback": H},
    }
    binding = replace(binding, physical_manifest_sha256=payload_sha256(payload))
    envelope = {"binding": binding.as_dict(), **payload}
    return binding, profile, envelope


class PhysicalUsageTests(unittest.TestCase):
    def test_closed_snapshot_normalizes_exact_bindings_and_unknown_details(self):
        binding, profile, envelope = fixture()
        manifest, usages, components, absent = normalize_capture(
            envelope, binding, (profile,), ("answer", "fallback")
        )
        self.assertEqual(manifest.expected_call_ids, ("physical",))
        self.assertEqual(manifest.calls[0].request_sha256, "f" * 64)
        self.assertEqual(usages["physical"].cache_read_tokens, 2)
        self.assertIsNone(usages["physical"].cache_write_tokens)
        self.assertIsNone(usages["physical"].reasoning_tokens)
        self.assertEqual(components, {"answer": ("physical",)})
        self.assertEqual(absent, {"fallback": H})

    def test_incomplete_forged_duplicate_or_cross_attempt_data_refuses(self):
        binding, profile, original = fixture()
        for mutate in (
            lambda e: e["binding"].update(owner="other"),
            lambda e: e["snapshot"].update(complete=False),
            lambda e: e["snapshot"].update(root_id="other"),
            lambda e: e["snapshot"]["calls"][0].update(status_code=429),
            lambda e: e["snapshot"]["calls"][0].update(sequence=1),
            lambda e: e["snapshot"]["calls"].append(
                copy.deepcopy(e["snapshot"]["calls"][0])
            ),
            lambda e: e["snapshot"]["calls"][0]["usage"].update({"private": 1}),
            lambda e: e["absent_components"].clear(),
        ):
            envelope = copy.deepcopy(original)
            mutate(envelope)
            # Even authenticating the altered payload cannot make its semantics valid.
            envelope["binding"]["physical_manifest_sha256"] = payload_sha256(
                {
                    k: envelope[k]
                    for k in ("snapshot", "component_calls", "absent_components")
                }
            )
            changed_binding = replace(
                binding,
                physical_manifest_sha256=envelope["binding"][
                    "physical_manifest_sha256"
                ],
            )
            with self.assertRaises(UsageRatingRefused):
                normalize_capture(
                    envelope, changed_binding, (profile,), ("answer", "fallback")
                )

    def test_snapshot_digest_and_profile_provider_model_are_frozen(self):
        binding, profile, envelope = fixture()
        envelope["snapshot"]["calls"][0]["usage"]["usage.prompt_tokens"] = 11
        with self.assertRaises(UsageRatingRefused):
            normalize_capture(envelope, binding, (profile,), ("answer", "fallback"))
        _, _, envelope = fixture()
        with self.assertRaises(UsageRatingRefused):
            normalize_capture(
                envelope,
                binding,
                (replace(profile, model="other"),),
                ("answer", "fallback"),
            )

    def test_same_owner_closure_claims_before_completion_and_keeps_null_cache(self):
        binding, profile, envelope = fixture()
        card = TariffCard(
            "1",
            "constant_peak",
            "https://example.org/pricing",
            H,
            10,
            10,
            100,
            (
                TariffRate(
                    "provider",
                    "model",
                    "0.0000001",
                    "0.00000002",
                    "0.0000001",
                    "0.0000004",
                    "0",
                ),
            ),
        )
        binding = replace(binding, tariff_sha256=card.sha256())
        envelope["binding"] = binding.as_dict()
        source = object.__new__(PrivateCaptureClient)
        source.owner, source.collector_uid = "owner", os.geteuid()
        source.closed = lambda b: copy.deepcopy(envelope)
        source.persist_audit = lambda b, report: events.append(("audit", report))
        authority = object.__new__(PrivateCollectorClient)
        authority.owner, authority.collector_uid = "owner", os.geteuid()
        events = []
        authority._send = lambda method, raw, prefix="/spending/": events.append(
            (method, raw)
        )
        collector = PhysicalUsageCollector(
            source, authority, card, card.sha256(), (profile,), ("answer", "fallback")
        )
        attempt = {
            "attempt_id": binding.attempt_id,
            "budget_owner": "owner",
            "route": binding.route_sha256,
            "cost_basis": "audited_usage_rated",
            "tariff_sha256": card.sha256(),
            "mode": "live",
        }
        call = {
            "call_id": binding.call_id,
            "scope_sha256": binding.scope_sha256,
            "request_sha256": binding.request_sha256,
        }
        response = call | {"physical_manifest_sha256": binding.physical_manifest_sha256}
        receipt = collector.settle(attempt, call, response)
        self.assertEqual(
            [e[0] for e in events], ["claim_receipts", "audit", "complete"]
        )
        self.assertEqual(
            events[1][1]["capture_sha256"], binding.physical_manifest_sha256
        )
        self.assertEqual(events[1][1]["usage_schema_profiles"], [profile.as_dict()])
        self.assertIsNone(events[1][1]["receipts"][0]["usage"]["cache_write_tokens"])
        self.assertEqual(receipt["usage_rated_microusd"], 3)
        self.assertEqual(receipt["usage_rated_usd"], "0.00000244")
        self.assertTrue(receipt["all_calls_complete"])
        self.assertNotIn("billed_microusd", receipt)

        events.clear()

        def lost_audit_ack(binding, report):
            raise RuntimeError("private artifact detail")

        source.persist_audit = lost_audit_ack
        with self.assertRaisesRegex(
            UsageRatingRefused, "capture_audit_outcome_unknown"
        ):
            collector.settle(attempt, call, response)
        self.assertEqual([e[0] for e in events], ["claim_receipts"])

    def test_collector_role_cannot_reserve_bootstrap_or_revoke(self):
        client = object.__new__(PrivateCollectorClient)
        client.collector_uid = os.geteuid()
        for method in ("reserve", "begin", "initialize", "admit_attempt", "revoke"):
            with self.assertRaisesRegex(ControlRefused, "role_denied"):
                client(method, {})

    def test_boolean_schema_cannot_alias_integer_binding(self):
        binding, profile, envelope = fixture()
        envelope["binding"]["schema"] = True
        with self.assertRaises(UsageRatingRefused):
            normalize_capture(envelope, binding, (profile,), ("answer", "fallback"))

    def test_collector_rejects_cross_role_or_dual_billing_payload_before_transport(
        self,
    ):
        client = object.__new__(PrivateCollectorClient)
        client.collector_uid = os.geteuid()
        client._send = lambda *args, **kwargs: self.fail(
            "invalid payload reached transport"
        )
        base = {
            "call_id": "logical",
            "scope_sha256": H,
            "request_sha256": H,
            "manifest_sha256": H,
            "generation_ids": ["usage_" + H],
        }
        for bad in (
            base | {"generation_ids": ["provider_generation"]},
            base | {"unknown": "private"},
        ):
            with self.assertRaises(ControlRefused):
                client("claim_receipts", bad)
        complete = base | {
            "route_sha256": H,
            "components": {"answer": H},
            "usage_rating": {
                "tariff_sha256": H,
                "audit_sha256": H,
                "usage_rated_microusd": 1,
            },
            "billed_microusd": 1,
        }
        with self.assertRaises(ControlRefused):
            client("complete", complete)

    def test_malformed_capture_types_fail_with_fixed_codes(self):
        binding, profile, original = fixture()
        for field in ("provider", "model", "role"):
            envelope = copy.deepcopy(original)
            envelope["snapshot"]["calls"][0][field] = ["private"]
            digest = payload_sha256(
                {
                    k: envelope[k]
                    for k in ("snapshot", "component_calls", "absent_components")
                }
            )
            envelope["binding"]["physical_manifest_sha256"] = digest
            with self.assertRaises(UsageRatingRefused):
                normalize_capture(
                    envelope,
                    replace(binding, physical_manifest_sha256=digest),
                    (profile,),
                    ("answer", "fallback"),
                )

    def test_reviewed_embedding_no_output_normalizes_and_rates_unknown_cache(self):
        binding, answer_profile, envelope = fixture()
        embedding_profile = replace(
            answer_profile,
            version="embedding-v1",
            model="embedding-model",
            roles=("embedding",),
            input_path="usage.input_tokens",
            output_path=None,
            output_semantics="embedding_no_output",
            cache_read_path=None,
            reasoning_path=None,
        )
        embedding = copy.deepcopy(envelope["snapshot"]["calls"][0])
        embedding.update(
            sequence=1,
            permit_id="embedding-call",
            role="embedding",
            model="embedding-model",
            usage={"usage.input_tokens": 6},
        )
        envelope["snapshot"]["calls"].append(embedding)
        envelope["component_calls"]["embedding"] = ["embedding-call"]
        digest = payload_sha256(
            {
                k: envelope[k]
                for k in ("snapshot", "component_calls", "absent_components")
            }
        )
        binding = replace(binding, physical_manifest_sha256=digest)
        envelope["binding"] = binding.as_dict()
        manifest, usages, _, _ = normalize_capture(
            envelope,
            binding,
            (answer_profile, embedding_profile),
            ("answer", "embedding", "fallback"),
        )
        usage = usages["embedding-call"]
        self.assertEqual(usage.output_tokens, 0)
        self.assertIsNone(usage.cache_read_tokens)
        self.assertIsNone(usage.cache_write_tokens)
        card = TariffCard(
            "1",
            "constant_peak",
            "https://example.org/pricing",
            H,
            10,
            10,
            100,
            (
                TariffRate(
                    "provider",
                    "model",
                    "0.0000001",
                    "0.00000002",
                    "0.0000001",
                    "0.0000004",
                    "0",
                ),
                TariffRate(
                    "provider",
                    "embedding-model",
                    "0.0000001",
                    "0.0000001",
                    "0.0000001",
                    "0",
                    "0",
                ),
            ),
        )
        report = UsageRatedCollector(
            card, card.sha256(), lambda c: usages[c.call_id]
        ).collect(manifest)
        self.assertEqual(report["usage_rated_usd"], "0.00000304")
        self.assertIsNone(report["receipts"][1]["usage"]["cache_read_tokens"])
        self.assertIsNone(report["receipts"][1]["usage"]["cache_write_tokens"])
        with self.assertRaises(UsageRatingRefused):
            normalize_capture(
                envelope,
                binding,
                (
                    answer_profile,
                    replace(
                        embedding_profile, output_semantics="inclusive_output_total"
                    ),
                ),
                ("answer", "embedding", "fallback"),
            )

    def test_capture_methods_send_exact_binding_and_require_durable_audit_ack(self):
        binding, _, envelope = fixture()
        client = object.__new__(PrivateCaptureClient)
        client.owner, client.collector_uid = "owner", os.geteuid()
        events = []
        report = {"source": "audited_usage_rated", "receipts": []}
        report["audit_sha256"] = payload_sha256(report)
        ack = {"audit_sha256": report["audit_sha256"], "stored": True}

        def send(method, raw, prefix):
            events.append((method, json.loads(raw), prefix))
            return envelope if method == "closed" else ack

        client._send = send
        self.assertEqual(client.closed(binding), envelope)
        client.persist_audit(binding, report)
        self.assertEqual(
            events,
            [
                ("closed", binding.as_dict(), "/capture/"),
                ("audit", {"binding": binding.as_dict(), "audit": report}, "/capture/"),
            ],
        )
        for bad_ack in (
            {},
            None,
            {"audit_sha256": H, "stored": True},
            ack | {"stored": False},
            ack | {"stored": 1},
            ack | {"extra": "private"},
        ):
            ack = bad_ack
            with self.assertRaisesRegex(
                ControlRefused, "capture_audit_outcome_unknown"
            ):
                client.persist_audit(binding, report)
        events.clear()
        for bad_binding in (
            replace(binding, owner="other"),
            binding.as_dict(),
            replace(binding, schema=True),
        ):
            with self.assertRaises((ControlRefused, UsageRatingRefused)):
                client.closed(bad_binding)
            with self.assertRaises((ControlRefused, UsageRatingRefused)):
                client.persist_audit(bad_binding, report)
        for bad_report in (
            None,
            {},
            report | {"audit_sha256": H},
            report | {"unexpected": "private"},
        ):
            with self.assertRaises(ControlRefused):
                client.persist_audit(binding, bad_report)
        self.assertEqual(events, [])
