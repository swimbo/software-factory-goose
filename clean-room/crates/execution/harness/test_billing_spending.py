"""Collector settlement must use the same durable inference authority."""

import unittest

from billing_receipts import BillingRefused, PhysicalCall, freeze_manifest
from billing_spending import collect_for_spending


class BillingSpending(unittest.TestCase):
    def test_claim_precedes_lookup_complete_binds_all_components(self):
        events = []
        first = "gen_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        second = "gen_01ARZ3NDEKTSV4RRFFQ69G5FAW"
        calls = tuple(
            PhysicalCall(
                name, i, name, "openai", "openai/fixture", gen, "vercel_generation"
            )
            for i, (name, gen) in enumerate((("classifier", first), ("answer", second)))
        )
        manifest = freeze_manifest(
            attempt_id="attempt",
            parent_request_id="parent",
            route_sha256="a" * 64,
            request_sha256="b" * 64,
            expected_call_ids=("classifier", "answer"),
            calls=calls,
        )

        def authority(method, body):
            events.append((method, body))
            return None

        class Client:
            def lookup(self, generation):
                self_test.assertEqual(events[0][0], "claim_receipts")
                return (
                    '{"data":{"id":"%s","provider_name":"openai",'
                    '"model":"openai/fixture","is_byok":false,'
                    '"total_cost":0.000001,"gateway_cost":0.000001,"usage":0.000001}}'
                    % generation
                ).encode()

        self_test = self
        kwargs = dict(
            authority=authority,
            client=Client(),
            call_id="call",
            scope_sha256="c" * 64,
            route_sha256="a" * 64,
            request_sha256="b" * 64,
            expected_components=("classifier", "answer", "fallback"),
            component_calls={"classifier": ("classifier",), "answer": ("answer",)},
            absent_components={"fallback": "d" * 64},
        )
        result = collect_for_spending(manifest, **kwargs)
        self.assertEqual(result["billed_microusd"], 2)
        self.assertEqual([e[0] for e in events], ["claim_receipts", "complete"])
        completion = events[-1][1]
        self.assertEqual(
            set(completion["components"]), set(kwargs["expected_components"])
        )
        self.assertEqual(completion["generation_ids"], [first, second])
        self.assertEqual(completion["request_sha256"], "b" * 64)
        self.assertEqual(completion["manifest_sha256"], events[0][1]["manifest_sha256"])
        for changed in (
            {"request_sha256": "e" * 64},
            {"route_sha256": "e" * 64},
            {"absent_components": {}},
            {
                "component_calls": {
                    "classifier": ("classifier", "answer"),
                    "answer": ("answer",),
                }
            },
        ):
            events.clear()
            with self.assertRaises(BillingRefused):
                collect_for_spending(manifest, **(kwargs | changed))
            self.assertEqual(events, [])

    def test_failed_durable_claim_never_looks_up_or_settles(self):
        from unittest.mock import Mock

        call = PhysicalCall(
            "answer",
            0,
            "answer",
            "openai",
            "fixture",
            "gen_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "vercel_generation",
        )
        manifest = freeze_manifest(
            attempt_id="attempt",
            parent_request_id="parent",
            route_sha256="a" * 64,
            request_sha256="b" * 64,
            expected_call_ids=("answer",),
            calls=(call,),
        )
        authority = Mock(side_effect=RuntimeError("private detail"))
        client = Mock()
        with self.assertRaisesRegex(BillingRefused, "authority_unavailable") as caught:
            collect_for_spending(
                manifest,
                authority=authority,
                client=client,
                call_id="call",
                scope_sha256="c" * 64,
                route_sha256="a" * 64,
                request_sha256="b" * 64,
                expected_components=("answer",),
                component_calls={"answer": ("answer",)},
                absent_components={},
            )
        self.assertNotIn("private", str(caught.exception))
        client.lookup.assert_not_called()
        self.assertEqual(authority.call_count, 1)


if __name__ == "__main__":
    unittest.main()
