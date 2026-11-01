"""Metadata-only broker RPC; real UID/journal integration is a native replay."""

import json
import unittest
from unittest.mock import patch

from physical_settlement import (
    PrivateSettlementClient,
    ProtectedUsageSettlement,
    settlement_request,
    validate_request,
)
from protected_spending_control import ControlRefused


def inputs():
    attempt = dict(
        attempt_id="run_" + "a" * 64,
        budget_owner="owner",
        route="b" * 64,
        mode="live",
        cost_basis="audited_usage_rated",
        tariff_sha256="c" * 64,
        prompt="never sent to collector",
    )
    call = dict(
        call_id="call",
        scope_sha256="d" * 64,
        request_sha256="e" * 64,
        sequence=0,
        request_bytes=100,
        output_tokens=10,
    )
    response = {k: call[k] for k in ("call_id", "scope_sha256", "request_sha256")}
    response.update(physical_manifest_sha256="f" * 64, sse=b"secret-provider-output")
    receipt = {k: response[k] for k in response if k != "sse"}
    receipt.update(
        route_sha256=attempt["route"],
        tariff_sha256=attempt["tariff_sha256"],
        billing_receipt_sha256="1" * 64,
        audit_sha256="2" * 64,
        usage_rated_microusd=2,
        usage_rated_usd="0.000002",
        source="audited_usage_rated",
        all_calls_complete=True,
    )
    return attempt, call, response, receipt


class SettlementTests(unittest.TestCase):
    def client(self):
        # Exercise broker projection/receipt validation without impersonating a
        # kernel peer. Native replay constructs the actual protected Unix client.
        client = object.__new__(PrivateSettlementClient)
        client.broker_uid, client.owner = 2005, "owner"
        client.route, client.tariff, client.mode = "b" * 64, "c" * 64, "live"
        return client

    def test_projection_excludes_prompt_and_provider_bytes(self):
        attempt, call, response, _ = inputs()
        request = settlement_request(attempt, call, response)
        raw = json.dumps(request)
        self.assertNotIn("never sent", raw)
        self.assertNotIn("secret-provider-output", raw)
        self.assertNotIn("sse", request["response"])
        self.assertEqual(request["attempt"]["attempt_id"], attempt["attempt_id"])
        self.assertEqual(request["response"]["request_sha256"], call["request_sha256"])
        with self.assertRaises(ControlRefused):
            settlement_request(attempt, call | {"secret": "no"}, response)
        with self.assertRaises(ControlRefused):
            settlement_request(attempt, call, response | {"scope_sha256": "0" * 64})

    def test_rpc_sends_only_metadata_and_validates_exact_result(self):
        attempt, call, response, receipt = inputs()
        seen = []
        client = self.client()

        def send(method, raw, prefix):
            seen.append((method, json.loads(raw), prefix))
            return receipt

        with (
            patch("physical_settlement.os.geteuid", return_value=2005),
            patch.object(client, "_send", send),
        ):
            self.assertEqual(client.settle(attempt, call, response), receipt)
        self.assertEqual(seen[0][0], "settle")
        self.assertEqual(seen[0][2], "/settlement/")
        self.assertNotIn("sse", seen[0][1]["response"])
        for changes in (
            {"secret": "not returned"},
            {"all_calls_complete": False},
            {"request_sha256": "0" * 64},
            {"usage_rated_usd": "0.000003"},
        ):
            with (
                self.subTest(changes=changes),
                patch("physical_settlement.os.geteuid", return_value=2005),
                patch.object(client, "_send", return_value=receipt | changes),
            ):
                with self.assertRaises(ControlRefused):
                    client.settle(attempt, call, response)

    def test_service_refuses_unprojected_content_and_foreign_roles(self):
        from types import SimpleNamespace
        from physical_usage import PhysicalUsageCollector

        attempt, call, response, _ = inputs()
        safe = settlement_request(attempt, call, response)
        with self.assertRaises(ControlRefused):
            validate_request(safe | {"secret": "not metadata"})
        with self.assertRaises(ControlRefused):
            validate_request(safe | {"response": response})
        with patch("physical_settlement.os.geteuid", return_value=2006):
            with self.assertRaises(ControlRefused):
                ProtectedUsageSettlement(
                    object(), broker_uid=2005, worker_uid=2001, route_sha256="b" * 64
                )
        # This state-only test supplies no authenticated clients and cannot settle.
        # It proves foreign kernel identities/methods fail before collection.
        collector = object.__new__(PhysicalUsageCollector)
        collector.source = SimpleNamespace(collector_uid=2006)
        with patch("physical_settlement.os.geteuid", return_value=2005):
            with self.assertRaises(ControlRefused):
                ProtectedUsageSettlement(
                    collector, broker_uid=2005, worker_uid=2001, route_sha256="b" * 64
                )
        backend = object.__new__(ProtectedUsageSettlement)
        backend.broker_uid = 2005
        for uid, method in (
            (0, "settle"),
            (2001, "settle"),
            (2006, "settle"),
            (2007, "settle"),
            (2005, "begin"),
        ):
            with (
                self.subTest(uid=uid, method=method),
                self.assertRaisesRegex(ControlRefused, "settlement_role_denied"),
            ):
                backend.dispatch(uid, method, safe)

    def test_wrong_uid_and_binding_do_not_dispatch_and_unknown_never_retries(self):
        attempt, call, response, _ = inputs()
        client = self.client()
        with (
            patch("physical_settlement.os.geteuid", return_value=2007),
            patch.object(client, "_send") as send,
        ):
            with self.assertRaises(ControlRefused):
                client.settle(attempt, call, response)
            send.assert_not_called()
        with (
            patch("physical_settlement.os.geteuid", return_value=2005),
            patch.object(client, "_send") as send,
        ):
            with self.assertRaises(ControlRefused):
                client.settle(attempt | {"route": "0" * 64}, call, response)
            send.assert_not_called()
        with (
            patch("physical_settlement.os.geteuid", return_value=2005),
            patch.object(
                client, "_send", side_effect=OSError("lost receipt acknowledgement")
            ) as send,
        ):
            with self.assertRaisesRegex(ControlRefused, "settlement_outcome_unknown"):
                client.settle(attempt, call, response)
            self.assertEqual(send.call_count, 1)


if __name__ == "__main__":
    unittest.main()
