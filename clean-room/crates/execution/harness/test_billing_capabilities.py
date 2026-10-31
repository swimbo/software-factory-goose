"""Read-only provider metadata must never become paid-call authorization."""

import unittest

from billing_capabilities import BillablePath, assess_receipt_sources, factory_paths


class BillingCapabilities(unittest.TestCase):
    def test_unchanged_factory_route_blocks_every_unproven_billing_path(self):
        result = assess_receipt_sources("a" * 64, factory_paths())
        self.assertFalse(result["documented_per_request_coverage"])
        self.assertFalse(result["allows_live_inference"])
        reasons = {b["reason"] for b in result["blockers"]}
        self.assertEqual(
            reasons,
            {
                "aggregate_not_per_request_billing",
                "embedding_receipt_contract_unverified",
            },
        )
        self.assertEqual(result["route_sha256"], "a" * 64)
        self.assertIn(
            "/api/balance", result["evidence"]["ollama"]["documented_metadata_paths"]
        )

    def test_documented_vercel_chat_lookup_is_not_a_live_admission(self):
        result = assess_receipt_sources(
            "b" * 64,
            (
                BillablePath(
                    "classifier", "vercel-classifier", "openai/gpt-6-luna", "chat"
                ),
            ),
        )
        self.assertTrue(result["documented_per_request_coverage"])
        self.assertFalse(result["allows_live_inference"])
        self.assertEqual(result["blockers"], [])
        self.assertEqual(
            result["required_actual_evidence"],
            [
                "authenticated_complete_dispatch_manifest",
                "correlated_provider_recorded_receipts",
                "reviewed_enforceable_all_path_charge_bounds",
            ],
        )

    def test_unknown_or_malformed_scope_cannot_fall_through_to_supported_lookup(self):
        for route, paths in (
            ("wrong", factory_paths()),
            ("a" * 64, ()),
            (
                "a" * 64,
                [BillablePath("id", "vercel-classifier", "openai/gpt-6-luna", "chat")],
            ),
            ("a" * 64, (BillablePath("id", "other", "openai/gpt-6-luna", "chat"),)),
            (
                "a" * 64,
                (BillablePath("id", "vercel-classifier", "unreviewed", "chat"),),
            ),
            (
                "a" * 64,
                (
                    BillablePath(
                        "id", "vercel-classifier", "openai/gpt-6-luna", "embedding"
                    ),
                ),
            ),
        ):
            with self.subTest(route=route, paths=paths):
                result = assess_receipt_sources(route, paths)
                self.assertFalse(result["documented_per_request_coverage"])
                self.assertFalse(result["allows_live_inference"])
                self.assertTrue(result["blockers"])

    def test_metadata_account_isolation_and_prices_cannot_override_capability(self):
        # A per-key budget or a claimed exclusive account is not a request debit receipt.
        for model in ("deepseek-v4.1-flash:1017", "deepseek-v4-pro:0813"):
            result = assess_receipt_sources(
                "a" * 64, (BillablePath("answer", "ollama-cloud", model, "chat"),)
            )
            self.assertEqual(
                result["blockers"][0]["reason"], "aggregate_not_per_request_billing"
            )
            self.assertIsNone(result["paths"][0]["receipt_endpoint"])


if __name__ == "__main__":
    unittest.main()
