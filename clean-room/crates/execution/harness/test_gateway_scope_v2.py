"""Versioned scope handoff; fixtures do not establish native socket custody."""

import copy
import base64
import time
import unittest
from unittest.mock import Mock

from gateway_custody import GatewayAcquisitionAuthority
from physical_usage import payload_sha256
from protected_spending_control import ControlRefused
from test_scope_preimage_v2 import legacy_scope
from linux_supervisor import factory_scope_digest
from linux_runner import PrivateRootSupervisorClient
from gateway_transport import PrivateGatewayClient, ProtectedGatewayTransport
from factory_harness import canonical
from protected_spending_control import binding_digest


class GatewayScopeV2Tests(unittest.TestCase):
    def fixture(self):
        scope = legacy_scope()
        scope["route"]["usage_tariff_sha256"] = "a" * 64
        digest = factory_scope_digest(scope)
        root = {
            "schema": 1,
            "owner": "owner",
            "attempt_id": "run_" + "a" * 64,
            "call_id": "call",
            "scope_sha256": digest,
            "route_sha256": scope["route"]["route_sha256"],
            "request_sha256": "b" * 64,
            "tariff_sha256": "a" * 64,
        }
        call = {
            "call_id": "call",
            "scope_sha256": digest,
            "request_sha256": "b" * 64,
            "sequence": 0,
            "request_bytes": 100,
            "output_tokens": 10,
        }
        begin = Mock(return_value=True)
        opened = Mock(
            side_effect=lambda b: {"root_sha256": payload_sha256(b), "opened": True}
        )
        authority = GatewayAcquisitionAuthority(begin, opened, gateway_uid=2007)
        return scope, root, call, authority, begin, opened

    def test_v2_exact_one_use_ack_and_version_separation(self):
        scope, root, call, authority, begin, opened = self.fixture()
        authority.arm_v2(root, call, scope, 1000)
        request = {"binding": root, "call": call}
        with self.assertRaises(ControlRefused):
            authority.acquire(2007, request)
        self.assertEqual(begin.call_count, 0)
        expected = {
            "schema": 2,
            "root_sha256": payload_sha256(root),
            "acquired": True,
            "scope": scope,
            "root_deadline_ms": 1000,
        }
        self.assertEqual(authority.acquire_v2(2007, request), expected)
        with self.assertRaises(ControlRefused):
            authority.acquire_v2(2007, request)
        self.assertEqual((begin.call_count, opened.call_count), (1, 1))

    def test_scope_snapshot_is_copied_and_only_gateway_uid_may_acquire(self):
        scope, root, call, authority, begin, _ = self.fixture()
        original = copy.deepcopy(scope)
        authority.arm_v2(root, call, scope, 1000)
        scope["worker"] = "changed"
        with self.assertRaises(ControlRefused):
            authority.acquire_v2(2001, {"binding": root, "call": call})
        self.assertEqual(begin.call_count, 0)
        result = authority.acquire_v2(2007, {"binding": root, "call": call})
        self.assertEqual(result["scope"], original)

    def test_unknown_ack_never_rearms_or_retries_begin(self):
        scope, root, call, authority, begin, opened = self.fixture()
        opened.side_effect = OSError("lost public fixture acknowledgement")
        authority.arm_v2(root, call, scope, 1000)
        for _ in range(2):
            with self.assertRaises(ControlRefused):
                authority.acquire_v2(2007, {"binding": root, "call": call})
        with self.assertRaises(ControlRefused):
            authority.arm_v2(root, call, scope, 1000)
        self.assertEqual((begin.call_count, opened.call_count), (1, 1))

    def test_invalid_or_extended_root_deadline_never_arms(self):
        for deadline in (True, 0, -1, 172800001):
            scope, root, call, authority, begin, opened = self.fixture()
            with self.subTest(deadline=deadline), self.assertRaises(ControlRefused):
                authority.arm_v2(root, call, scope, deadline)
            self.assertEqual(authority.roots, {})
            self.assertEqual((begin.call_count, opened.call_count), (0, 0))

    def test_v1_armed_root_cannot_be_acquired_as_v2(self):
        _, root, call, authority, begin, _ = self.fixture()
        authority.arm(root, call)
        with self.assertRaises(ControlRefused):
            authority.acquire_v2(2007, {"binding": root, "call": call})
        self.assertEqual(begin.call_count, 0)

    def test_changed_scope_route_or_tariff_never_arms(self):
        scope, root, call, authority, begin, opened = self.fixture()
        for value in (
            scope | {"worker": "changed"},
            scope | {"route": scope["route"] | {"route_sha256": "0" * 64}},
            scope | {"route": scope["route"] | {"usage_tariff_sha256": "0" * 64}},
        ):
            with self.subTest(value=value), self.assertRaises(ControlRefused):
                authority.arm_v2(root, call, value, 1000)
        self.assertEqual(authority.roots, {})
        self.assertEqual((begin.call_count, opened.call_count), (0, 0))

    def test_binding_route_and_tariff_must_match_valid_scope(self):
        scope, root, call, authority, begin, opened = self.fixture()
        for field in ("route_sha256", "tariff_sha256"):
            changed = root | {field: "0" * 64}
            with self.subTest(field=field), self.assertRaises(ControlRefused):
                authority.arm_v2(changed, call, scope, 1000)
        self.assertEqual(authority.roots, {})
        self.assertEqual((begin.call_count, opened.call_count), (0, 0))

    def test_transport_reads_scope_from_root_before_arming_v2(self):
        from unittest.mock import patch

        scope, root, call, authority, begin, _ = self.fixture()
        request = {"model": "auto", "messages": [], "tools": [], "max_tokens": 10}
        call["request_sha256"] = binding_digest(request)
        call["request_bytes"] = len(canonical(request).encode())
        root["request_sha256"] = call["request_sha256"]
        attempt = {
            "attempt_id": root["attempt_id"],
            "budget_owner": "owner",
            "route": root["route_sha256"],
            "tariff_sha256": root["tariff_sha256"],
            "mode": "rehearsal",
            "cost_basis": "audited_usage_rated",
        }
        grant = {
            "attempt_id": root["attempt_id"],
            "owner": "owner",
            "route_sha256": root["route_sha256"],
            "tariff_sha256": root["tariff_sha256"],
            "scope_sha256": root["scope_sha256"],
            "expires_at_ms": time.time_ns() // 1000000 + 10000,
        }
        root_client = object.__new__(PrivateRootSupervisorClient)
        root_client.broker_uid = 2005
        root_client._request = Mock(
            return_value={
                "schema": 2,
                "scope_sha256": root["scope_sha256"],
                "scope": scope,
                "root_deadline_ms": 1000,
            }
        )
        client = object.__new__(PrivateGatewayClient)
        client.owner, client.service_uid, client.broker_uid = "owner", 2007, 2005

        def send(method, raw, prefix, **kwargs):
            import json

            frame = json.loads(raw)
            ack = authority.acquire_v2(
                2007, {"binding": frame["binding"], "call": frame["call"]}
            )
            self.assertEqual(ack["scope"], scope)
            self.assertEqual(ack["root_deadline_ms"], 1000)
            return {
                k: call[k] for k in ("call_id", "scope_sha256", "request_sha256")
            } | {
                "physical_manifest_sha256": "5" * 64,
                "sse": base64.b64encode(b"data: [DONE]\n\n").decode(),
            }

        client._send = send
        transport = object.__new__(ProtectedGatewayTransport)
        transport.journal, transport.acquisition, transport.client = (
            object(),
            authority,
            client,
        )
        authority.protected_uid = 2005
        transport.owner, transport.route, transport.tariff, transport.mode = (
            "owner",
            root["route_sha256"],
            root["tariff_sha256"],
            "rehearsal",
        )
        transport._scope_client = root_client
        with patch("gateway_transport.os.geteuid", return_value=2005):
            result = transport.exchange_reserved(attempt, grant, call, request)
        self.assertEqual(result["sse"], b"data: [DONE]\n\n")
        self.assertEqual(begin.call_count, 1)
        root_client._request.assert_called_once_with(
            "/harness-launch/scope_preimage_v2",
            {"attempt": attempt, "scope_sha256": root["scope_sha256"]},
        )
        transport.mode = "live"
        attempt["mode"] = "live"
        transport._scope_client = None
        with patch("gateway_transport.os.geteuid", return_value=2005):
            with self.assertRaisesRegex(ControlRefused, "gateway_scope_required"):
                transport.exchange_reserved(attempt, grant, call, request)
        self.assertEqual(begin.call_count, 1)


if __name__ == "__main__":
    unittest.main()
