import unittest
from dataclasses import replace
from usage_rating import (
    TariffRate,
    TariffCard,
    PhysicalCall,
    Manifest,
    UsageEvidence,
    UsageRatedCollector,
    UsageRatingRefused,
)

H = "a" * 64


class UsageRatingTests(unittest.TestCase):
    def setUp(self):
        self.rate = TariffRate(
            "provider",
            "model",
            "0.0000001",
            "0.00000002",
            "0.0000003",
            "0.0000004",
            "0",
        )
        self.card = TariffCard(
            "1",
            "constant_peak",
            "https://example.org/pricing",
            H,
            10,
            10,
            100,
            (self.rate,),
        )
        self.call = PhysicalCall("c", 0, "answer", "provider", "model", H, 20)
        self.manifest = Manifest("attempt", "parent", H, H, ("c",), (self.call,))
        self.e = UsageEvidence(
            "c", "provider", "model", H, 10, 2, 3, 4, 1, H, "complete"
        )

    def collect(self, e=None, m=None, card=None):
        card = card or self.card
        return UsageRatedCollector(card, card.sha256(), lambda c: e or self.e).collect(
            m or self.manifest
        )

    def test_arithmetic(self):
        r = self.collect()
        self.assertEqual(r["usage_rated_usd"], "0.00000304")
        self.assertEqual(r["usage_rated_microusd"], 4)
        self.assertNotIn("billed_microusd", r)
        self.assertEqual(r["source"], "audited_usage_rated")

    def test_round_once(self):
        m = replace(
            self.manifest,
            expected_call_ids=("c", "d"),
            calls=(self.call, replace(self.call, call_id="d", sequence=1)),
        )
        e = replace(
            self.e,
            input_tokens=1,
            cache_read_tokens=0,
            cache_write_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
        )
        self.assertEqual(
            UsageRatedCollector(
                self.card, self.card.sha256(), lambda c: replace(e, call_id=c.call_id)
            ).collect(m)["usage_rated_microusd"],
            1,
        )

    def test_invalid_usage(self):
        for k, v in [
            ("cache_read_tokens", None),
            ("input_tokens", True),
            ("input_tokens", 2**63),
            ("output_tokens", -1),
            ("cache_write_tokens", 11),
            ("reasoning_tokens", 5),
            ("status", "error"),
            ("status", "partial"),
            ("model", "other"),
            ("request_sha256", "b" * 64),
        ]:
            with self.subTest(k=k, v=v), self.assertRaises(UsageRatingRefused):
                self.collect(replace(self.e, **{k: v}))

    def test_incomplete_manifest(self):
        for m in [
            replace(self.manifest, expected_call_ids=("c", "missing")),
            replace(self.manifest, calls=(self.call, self.call)),
            replace(self.manifest, calls=()),
            replace(self.manifest, calls=(replace(self.call, dispatched_at=100),)),
        ]:
            with self.assertRaises(UsageRatingRefused):
                self.collect(m=m)

    def test_tariff(self):
        for c in [
            replace(self.card, profile="dynamic"),
            replace(self.card, valid_until=10),
            replace(self.card, rates=(replace(self.rate, model="other"),)),
            replace(self.card, rates=(replace(self.rate, input_usd_per_token="NaN"),)),
        ]:
            with self.assertRaises(UsageRatingRefused):
                self.collect(card=c)
        with self.assertRaises(UsageRatingRefused):
            UsageRatedCollector(self.card, "b" * 64, lambda c: self.e)

    def test_audit_binding(self):
        import hashlib
        import json

        r = self.collect()
        digest = r.pop("audit_sha256")
        self.assertEqual(
            digest,
            hashlib.sha256(
                json.dumps(r, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        )
        self.assertEqual(r["tariff"], __import__("dataclasses").asdict(self.card))

    def test_unknown_reasoning_detail_is_preserved_when_total_output_is_complete(self):
        report = self.collect(replace(self.e, reasoning_tokens=None))
        self.assertIsNone(report["receipts"][0]["usage"]["reasoning_tokens"])
        self.assertEqual(report["usage_rated_usd"], "0.00000304")

    def test_rate_or_interval_change_breaks_frozen_binding(self):
        for card in [
            replace(self.card, valid_until=101),
            replace(self.card, rates=(replace(self.rate, output_usd_per_token="0.5"),)),
        ]:
            with self.assertRaises(UsageRatingRefused):
                UsageRatedCollector(card, self.card.sha256(), lambda c: self.e)

    def test_all_hidden_calls_required(self):
        hidden = replace(self.call, call_id="hidden", sequence=0, role="embedding")
        answer = replace(self.call, sequence=1)
        m = replace(
            self.manifest, expected_call_ids=("hidden", "c"), calls=(hidden, answer)
        )
        with self.assertRaises(UsageRatingRefused):
            self.collect(m=m)

    def test_missing_cost_inputs_never_become_zero(self):
        for field in (
            "input_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
            "output_tokens",
        ):
            with self.subTest(field=field), self.assertRaises(UsageRatingRefused):
                self.collect(replace(self.e, **{field: None}))
