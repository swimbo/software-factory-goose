"""Provider-recorded costs must remain distinct from estimates and aggregate deltas."""

from dataclasses import replace
from decimal import Decimal
import json
import subprocess
import unittest
from unittest.mock import patch

from billing_receipts import (
    BillingRefused,
    PhysicalCall,
    ReceiptCollector,
    VercelGenerationClient,
    freeze_manifest,
    parse_generation,
    _lookup_https,
)


GEN = "gen_01ARZ3NDEKTSV4RRFFQ69G5FAV"
OTHER = "gen_01ARZ3NDEKTSV4RRFFQ69G5FAW"


def payload(gen=GEN, model="openai/gpt-6-luna", cost="0.0000002"):
    return (
        '{"data":{"id":"%s","provider_name":"openai","model":"%s",'
        '"is_byok":false,"total_cost":%s,"gateway_cost":%s,"usage":%s}}'
        % (gen, model, cost, cost, cost)
    ).encode()


def call(gen=GEN, role="classifier", sequence=0):
    return PhysicalCall(
        call_id="call-" + str(sequence),
        sequence=sequence,
        role=role,
        provider="openai",
        model="openai/gpt-6-luna",
        generation_id=gen,
        receipt_source="vercel_generation",
    )


def manifest(calls=None, attempt="attempt-1"):
    calls = calls or (call(), call(OTHER, "answer", 1))
    return freeze_manifest(
        attempt_id=attempt,
        parent_request_id="parent-1",
        route_sha256="a" * 64,
        request_sha256="b" * 64,
        expected_call_ids=tuple(c.call_id for c in calls),
        calls=calls,
    )


class BillingReceipts(unittest.TestCase):
    def test_decimal_billed_amount_and_exact_provider_model_correlation(self):
        receipt = parse_generation(payload(), call())
        self.assertEqual(receipt.billed_usd, Decimal("0.0000002"))
        self.assertEqual(receipt.source, "vercel_generation")
        for changed in (
            replace(call(), model="other"),
            replace(call(), provider="other"),
            replace(call(), generation_id=OTHER),
        ):
            with self.assertRaises(BillingRefused):
                parse_generation(payload(), changed)

    def test_unknown_estimated_and_invalid_amounts_never_become_zero(self):
        for cost in ("null", "true", "NaN", "Infinity", "-1", '"1e999999"'):
            with self.subTest(cost=cost), self.assertRaises(BillingRefused):
                parse_generation(payload(cost=cost), call())
        for field, value in (
            ("is_byok", True),
            ("gateway_cost", 3),
            ("usage", None),
            ("estimated", True),
        ):
            data = json.loads(payload())
            data["data"][field] = value
            with self.assertRaises(BillingRefused):
                parse_generation(json.dumps(data).encode(), call())
        with self.assertRaises(BillingRefused):
            parse_generation(b'{"data":{"cost":0,"estimated":true}}', call())
        with self.assertRaises(BillingRefused):
            parse_generation(payload(), replace(call(), receipt_source="ollama_delta"))
        with self.assertRaises(BillingRefused):
            parse_generation(
                payload().replace(b'"data":', b'"data":{},"data":'), call()
            )

    def test_manifest_requires_complete_ordered_unique_physical_calls(self):
        m = manifest()
        with self.assertRaises(BillingRefused):
            freeze_manifest(
                attempt_id=m.attempt_id,
                parent_request_id=m.parent_request_id,
                route_sha256=m.route_sha256,
                request_sha256=m.request_sha256,
                expected_call_ids=("call-0", "call-1", "hidden-retry"),
                calls=m.calls,
            )
        for calls in (
            (call(),),
            (call(), call(GEN, "answer", 1)),
            (call(), call(OTHER, "answer", 3)),
        ):
            with self.assertRaises(BillingRefused):
                manifest(calls)

    def test_collection_claims_generation_ids_before_lookup_and_sums_all_roles(self):
        seen = {}

        def claim(ids, binding):
            if any(gen in seen and seen[gen] != binding for gen in ids):
                raise BillingRefused("generation_reused")
            seen.update(dict.fromkeys(ids, binding))

        class Client:
            def lookup(self, generation):
                self_test.assertIn(generation, seen)
                return payload(gen=generation)

        self_test = self
        collector = ReceiptCollector(Client(), claim)
        result = collector.collect(manifest())
        self.assertEqual(result["billed_usd"], "0.0000004")
        self.assertEqual(result["billed_microusd"], 1)
        self.assertEqual(len(result["receipts"]), 2)
        self.assertEqual(collector.collect(manifest()), result)
        with self.assertRaises(BillingRefused):
            collector.collect(manifest(attempt="attempt-2"))

    def test_embedding_and_fallback_are_not_omitted_from_total(self):
        calls = tuple(
            call("gen_01ARZ3NDEKTSV4RRFFQ69G5FA" + suffix, role, n)
            for n, (suffix, role) in enumerate(
                zip("VWXY", ("embedding", "classifier", "fallback", "answer"))
            )
        )

        class Client:
            def lookup(self, generation):
                return payload(gen=generation, cost="0.0000003")

        result = ReceiptCollector(Client(), lambda ids, binding: None).collect(
            manifest(calls)
        )
        self.assertEqual(result["billed_usd"], "0.0000012")
        self.assertEqual(result["billed_microusd"], 2)

    def test_partial_receipts_refuse_aggregate(self):
        class Missing:
            def lookup(self, generation):
                if generation == OTHER:
                    raise BillingRefused("receipt_pending")
                return payload()

        with self.assertRaisesRegex(BillingRefused, "receipt_pending"):
            ReceiptCollector(Missing(), lambda ids, binding: None).collect(manifest())

    def test_transport_fixed_endpoint_auth_and_bounded_response(self):
        class Response:
            status = 200
            length = len(payload())

            def getheader(self, key, default=None):
                return {
                    "Content-Type": "application/json",
                    "Content-Length": str(self.length),
                }.get(key, default)

            def read(self, limit):
                self_test.assertLessEqual(limit, 32769)
                return payload()

        class Connection:
            def __init__(self, host, **kwargs):
                self_test.assertEqual(host, "ai-gateway.vercel.sh")
                self_test.assertLessEqual(kwargs["timeout"], 5)

            def request(self, method, path, headers):
                self_test.assertEqual(
                    (method, path), ("GET", "/v1/generation?id=" + GEN)
                )
                self_test.assertEqual(
                    headers["Authorization"], "Bearer synthetic-fixture"
                )

            def getresponse(self):
                return Response()

            def close(self):
                pass

        self_test = self
        with patch("billing_receipts.http.client.HTTPSConnection", Connection):
            self.assertEqual(_lookup_https("synthetic-fixture", GEN), payload())
            Response.status = 302
            with self.assertRaises(BillingRefused):
                _lookup_https("synthetic-fixture", GEN)
            Response.status = 404
            with self.assertRaisesRegex(BillingRefused, "receipt_pending"):
                _lookup_https("synthetic-fixture", GEN)
            Response.status = 200
            Response.length += 1
            with self.assertRaises(BillingRefused):
                _lookup_https("synthetic-fixture", GEN)
            Response.length = 32769
            with self.assertRaises(BillingRefused):
                _lookup_https("synthetic-fixture", GEN)

    def test_process_deadline_and_errors_are_sanitized(self):
        client = VercelGenerationClient("synthetic-fixture")
        with patch(
            "billing_receipts.subprocess.run",
            side_effect=subprocess.TimeoutExpired("secret-bearing-command", 5),
        ):
            with self.assertRaisesRegex(BillingRefused, "receipt_timeout") as caught:
                client.lookup(GEN)
            self.assertNotIn("secret", str(caught.exception))
        with patch("billing_receipts.subprocess.run") as runner:
            runner.return_value = subprocess.CompletedProcess(
                [], 0, b"200\n" + payload(), b""
            )
            self.assertEqual(client.lookup(GEN), payload())
            kwargs = runner.call_args.kwargs
            self.assertEqual(kwargs["env"], {})
            self.assertEqual(kwargs["timeout"], 5)
            self.assertEqual(kwargs["cwd"], "/")
        with self.assertRaises(BillingRefused):
            client.lookup("https://secret.invalid/")


if __name__ == "__main__":
    unittest.main()
