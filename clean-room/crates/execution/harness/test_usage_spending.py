"""Audited usage closure uses the same journal; no inferred billed debit."""

from dataclasses import replace
import unittest
from usage_rating import UsageRatedCollector, UsageRatingRefused
import test_usage_rating as fixtures
from usage_spending import collect_usage_for_spending


class UsageSpending(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.UsageRatingTests()
        fixture.setUp()
        self.f = fixture
        self.events = []
        self.collector = UsageRatedCollector(
            fixture.card, fixture.card.sha256(), self.usage
        )
        self.kwargs = dict(
            authority=lambda method, body: self.events.append((method, body)),
            call_id="logical",
            scope_sha256="c" * 64,
            route_sha256=fixture.manifest.route_sha256,
            request_sha256=fixture.manifest.request_sha256,
            expected_components=("answer", "unused"),
            component_calls={"answer": ("c",)},
            absent_components={"unused": "d" * 64},
        )

    def usage(self, call):
        self.assertEqual(self.events[0][0], "claim_receipts")
        return replace(self.f.e, call_id=call.call_id)

    def test_claim_then_authenticated_rating_then_complete_without_billed_amount(self):
        report = collect_usage_for_spending(
            self.f.manifest, collector=self.collector, **self.kwargs
        )
        self.assertEqual([x[0] for x in self.events], ["claim_receipts", "complete"])
        claim, completion = self.events[0][1], self.events[1][1]
        self.assertEqual(
            completion["usage_rating"],
            {
                "tariff_sha256": self.f.card.sha256(),
                "audit_sha256": report["audit_sha256"],
                "usage_rated_microusd": 4,
            },
        )
        self.assertNotIn("billed_microusd", completion)
        self.assertEqual(claim["generation_ids"], completion["generation_ids"])
        self.assertTrue(
            all(
                x.startswith("usage_") and len(x) == 70 for x in claim["generation_ids"]
            )
        )
        self.assertEqual(set(completion["components"]), {"answer", "unused"})

    def test_bad_manifest_or_dispositions_never_claim(self):
        for manifest, changes in (
            (replace(self.f.manifest, expected_call_ids=("missing",)), {}),
            (self.f.manifest, {"absent_components": {}}),
            (self.f.manifest, {"component_calls": {"answer": ("c", "c")}}),
            (self.f.manifest, {"request_sha256": "e" * 64}),
        ):
            self.events.clear()
            with self.assertRaises(UsageRatingRefused):
                collect_usage_for_spending(
                    manifest, collector=self.collector, **(self.kwargs | changes)
                )
            self.assertEqual(self.events, [])

    def test_partial_usage_or_lost_claim_does_not_complete(self):
        self.collector.authenticate_usage = lambda _: replace(
            self.f.e, status="partial"
        )
        with self.assertRaises(UsageRatingRefused):
            collect_usage_for_spending(
                self.f.manifest, collector=self.collector, **self.kwargs
            )
        self.assertEqual([x[0] for x in self.events], ["claim_receipts"])
        self.events.clear()

        def failed(method, body):
            self.events.append((method, body))
            raise RuntimeError("private detail")

        with self.assertRaisesRegex(UsageRatingRefused, "authority_unavailable"):
            collect_usage_for_spending(
                self.f.manifest,
                collector=self.collector,
                **(self.kwargs | {"authority": failed}),
            )
        self.assertEqual([x[0] for x in self.events], ["claim_receipts"])


if __name__ == "__main__":
    unittest.main()
