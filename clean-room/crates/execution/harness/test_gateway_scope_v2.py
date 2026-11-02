"""Versioned scope handoff; fixtures do not establish native socket custody."""

import copy
import os
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

    def test_physical_confirmation_is_bound_sequenced_and_never_rebegins(self):
        scope, root, call, authority, begin, opened = self.fixture()
        check = Mock(return_value=True)
        authority.arm_v2(root, call, scope, 1000, verify=check)
        authority.acquire_v2(2007, {"binding": root, "call": call})
        request = {
            "binding": root,
            "call": call,
            "physical_sequence": 0,
            "physical_sha256": "c" * 64,
        }
        for uid, change in (
            (2001, {}),
            (2007, {"physical_sequence": 1}),
            (2007, {"physical_sha256": "bad"}),
            (2007, {"call": call | {"sequence": 1}}),
            (2007, {"call": call | {"sequence": False}}),
        ):
            with (
                self.subTest(uid=uid, change=change),
                self.assertRaises(ControlRefused),
            ):
                authority.verify_physical_v2(uid, request | change)
        check.assert_not_called()
        self.assertEqual(
            authority.verify_physical_v2(2007, request),
            {
                "verified": True,
                "root_sha256": payload_sha256(root),
                "physical_sequence": 0,
                "physical_sha256": "c" * 64,
            },
        )
        with self.assertRaises(ControlRefused):
            authority.verify_physical_v2(2007, request)
        self.assertEqual(
            authority.verify_physical_v2(
                2007,
                request
                | {
                    "physical_sequence": 1,
                    "physical_sha256": "d" * 64,
                },
            )["physical_sequence"],
            1,
        )
        self.assertEqual(
            (begin.call_count, opened.call_count, check.call_count), (1, 1, 2)
        )

    def test_physical_confirmation_lost_or_false_ack_fails_closed(self):
        for result in (False, None, OSError("lost")):
            scope, root, call, authority, begin, _ = self.fixture()
            check = (
                Mock(side_effect=result)
                if isinstance(result, Exception)
                else Mock(return_value=result)
            )
            authority.arm_v2(root, call, scope, 1000, verify=check)
            authority.acquire_v2(2007, {"binding": root, "call": call})
            request = {
                "binding": root,
                "call": call,
                "physical_sequence": 0,
                "physical_sha256": "c" * 64,
            }
            with self.subTest(result=result):
                for _ in range(2):
                    with self.assertRaises(ControlRefused):
                        authority.verify_physical_v2(2007, request)
                self.assertEqual((begin.call_count, check.call_count), (1, 1))

    def test_unverified_or_legacy_root_cannot_confirm_physical_call(self):
        for version in (1, 2):
            scope, root, call, authority, begin, _ = self.fixture()
            if version == 1:
                authority.arm(root, call)
                authority.acquire(2007, {"binding": root, "call": call})
            else:
                authority.arm_v2(root, call, scope, 1000)
                authority.acquire_v2(2007, {"binding": root, "call": call})
            with self.assertRaises(ControlRefused):
                authority.verify_physical_v2(
                    2007,
                    {
                        "binding": root,
                        "call": call,
                        "physical_sequence": 0,
                        "physical_sha256": "c" * 64,
                    },
                )
            self.assertEqual(begin.call_count, 1)

    def test_physical_confirmation_requires_same_kernel_peer(self):
        scope, root, call, authority, _, _ = self.fixture()
        check = Mock(return_value=True)
        authority.arm_v2(root, call, scope, 1000, verify=check)
        authority.acquire_v2(
            2007, {"binding": root, "call": call}, pid=123, start_ticks=99
        )
        request = {
            "binding": root,
            "call": call,
            "physical_sequence": 0,
            "physical_sha256": "c" * 64,
        }
        for pid in (None, 124):
            with self.subTest(pid=pid), self.assertRaises(ControlRefused):
                authority.verify_physical_v2(2007, request, pid=pid, start_ticks=99)
        with self.assertRaises(ControlRefused):
            authority.verify_physical_v2(2007, request, pid=123, start_ticks=100)
        check.assert_not_called()
        self.assertTrue(
            authority.verify_physical_v2(2007, request, pid=123, start_ticks=99)[
                "verified"
            ]
        )
        check.assert_called_once_with(123, 99, False)

    def test_peer_pin_liveness_and_retirement_are_fail_closed(self):
        scope, root, call, authority, _, _ = self.fixture()
        read_fd, write_fd = os.pipe()
        try:
            check = Mock(return_value=True)
            authority.arm_v2(root, call, scope, 1000, verify=check)
            authority.acquire_v2(
                2007,
                {"binding": root, "call": call},
                pid=123,
                start_ticks=99,
                peer_fd=read_fd,
            )
            owned_fd = authority.roots[payload_sha256(root)][8]
            self.assertNotEqual(owned_fd, read_fd)
            request = {
                "binding": root,
                "call": call,
                "physical_sequence": 0,
                "physical_sha256": "c" * 64,
            }
            self.assertTrue(
                authority.verify_physical_v2(2007, request, pid=123, start_ticks=99)[
                    "verified"
                ]
            )
            check.assert_called_once_with(123, 99, True)
            os.write(write_fd, b"x")
            with self.assertRaises(ControlRefused):
                authority.verify_physical_v2(
                    2007, request | {"physical_sequence": 1}, pid=123, start_ticks=99
                )
            authority.retire(root)
            with self.assertRaises(OSError):
                os.fstat(owned_fd)
            with self.assertRaises(ControlRefused):
                authority.verify_physical_v2(
                    2007, request | {"physical_sequence": 1}, pid=123, start_ticks=99
                )
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_peer_exit_during_root_check_never_confirms(self):
        scope, root, call, authority, _, _ = self.fixture()
        read_fd, write_fd = os.pipe()
        try:

            def verify(*_):
                os.write(write_fd, b"x")
                return True

            authority.arm_v2(root, call, scope, 1000, verify=verify)
            authority.acquire_v2(
                2007,
                {"binding": root, "call": call},
                pid=123,
                start_ticks=99,
                peer_fd=read_fd,
            )
            request = {
                "binding": root,
                "call": call,
                "physical_sequence": 0,
                "physical_sha256": "c" * 64,
            }
            for _ in range(2):
                with self.assertRaises(ControlRefused):
                    authority.verify_physical_v2(2007, request, pid=123, start_ticks=99)
            authority.retire(root)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_failed_begin_and_pin_limit_do_not_leak_handles(self):
        from unittest.mock import patch

        read_fd, write_fd = os.pipe()
        try:
            scope, root, call, authority, begin, _ = self.fixture()
            authority.arm_v2(root, call, scope, 1000, verify=Mock(return_value=True))
            with (
                patch("gateway_custody.MAX_PEER_PINS", 0),
                self.assertRaises(ControlRefused),
            ):
                authority.acquire_v2(
                    2007,
                    {"binding": root, "call": call},
                    pid=123,
                    start_ticks=99,
                    peer_fd=read_fd,
                )
            begin.assert_not_called()
            begin.return_value = False
            with self.assertRaises(ControlRefused):
                authority.acquire_v2(
                    2007,
                    {"binding": root, "call": call},
                    pid=123,
                    start_ticks=99,
                    peer_fd=read_fd,
                )
            self.assertIsNone(authority.roots[payload_sha256(root)][8])
            self.assertEqual(authority.roots[payload_sha256(root)][2], "unknown")
            authority.retire(root)
        finally:
            os.close(read_fd)
            os.close(write_fd)

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

        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
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
                2007,
                {"binding": frame["binding"], "call": frame["call"]},
                pid=123,
                start_ticks=99,
                peer_fd=read_fd,
            )
            self.assertEqual(ack["scope"], scope)
            self.assertEqual(ack["root_deadline_ms"], 1000)
            verified = authority.verify_physical_v2(
                2007,
                {
                    "binding": frame["binding"],
                    "call": frame["call"],
                    "physical_sequence": 0,
                    "physical_sha256": "c" * 64,
                },
                pid=123,
                start_ticks=99,
            )
            self.assertTrue(verified["verified"])
            return {
                k: call[k] for k in ("call_id", "scope_sha256", "request_sha256")
            } | {
                "physical_manifest_sha256": "5" * 64,
                "sse": base64.b64encode(b"data: [DONE]\n\n").decode(),
            }

        client._send = send
        transport = object.__new__(ProtectedGatewayTransport)
        transport.journal, transport.acquisition, transport.client = (
            Mock(return_value=True),
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
        with (
            patch("gateway_transport.os.geteuid", return_value=2005),
            patch("gateway_transport.time.time_ns", return_value=500_000_000),
        ):
            result = transport.exchange_reserved(attempt, grant, call, request)
        self.assertEqual(result["sse"], b"data: [DONE]\n\n")
        self.assertEqual(begin.call_count, 1)
        self.assertEqual(root_client._request.call_count, 2)
        root_client._request.assert_called_with(
            "/harness-launch/scope_preimage_v2",
            {"attempt": attempt, "scope_sha256": root["scope_sha256"]},
        )
        transport.journal.assert_called_once_with("verify_inflight", call)
        verify = authority.roots[payload_sha256(root)][5]
        initial = root_client._request.return_value
        with (
            patch("gateway_transport.os.geteuid", return_value=2005),
            patch("gateway_transport.time.time_ns", return_value=500_000_000),
        ):
            for changed in (
                initial | {"scope": scope | {"worker": "other"}},
                initial | {"scope": scope | {"attempt": True}},
                initial | {"scope_sha256": "0" * 64},
                initial | {"root_deadline_ms": 999},
                initial | {"root_deadline_ms": True},
                initial | {"schema": True},
                initial | {"unexpected": True},
            ):
                root_client._request.return_value = changed
                with self.subTest(changed=changed):
                    self.assertFalse(verify(None, None, False))
            root_client._request.return_value = initial
            transport.journal.return_value = False
            before = root_client._request.call_count
            self.assertFalse(verify(None, None, False))
            self.assertEqual(root_client._request.call_count, before)
            transport.journal.return_value = True
        with (
            patch("gateway_transport.os.geteuid", return_value=2005),
            patch("gateway_transport.time.time_ns", return_value=1_000_000_000),
        ):
            self.assertFalse(verify(None, None, False))
        # A live confirmation must ask Root about the kernel peer, not a
        # process identity carried in a model-controlled request.
        authority.roots.clear()
        transport.mode = "live"
        attempt["mode"] = "live"
        transport.journal.return_value = True
        root_client._request.side_effect = lambda path, value: (
            initial
            if path.endswith("scope_preimage_v2")
            else {
                "verified": True,
                "pid": value["pid"],
                "start_ticks": value["start_ticks"],
                "scope_sha256": value["scope_sha256"],
            }
        )
        with (
            patch("gateway_transport.os.geteuid", return_value=2005),
            patch("gateway_transport.time.time_ns", return_value=500_000_000),
        ):
            self.assertEqual(
                transport.exchange_reserved(attempt, grant, call, request)["sse"],
                b"data: [DONE]\n\n",
            )
            live_verify = authority.roots[payload_sha256(root)][5]
            self.assertFalse(live_verify(None, None, False))
            before = root_client._request.call_count
            self.assertFalse(live_verify(123, 99, False))
            self.assertEqual(root_client._request.call_count, before)
            root_client._request.side_effect = (
                lambda path, value: initial
                if path.endswith("scope_preimage_v2")
                else {
                    "verified": True,
                    "pid": 124,
                    "start_ticks": value["start_ticks"],
                    "scope_sha256": value["scope_sha256"],
                }
            )
            self.assertFalse(live_verify(123, 99, True))
            root_client._request.side_effect = (
                lambda path, value: initial
                if path.endswith("scope_preimage_v2")
                else {
                    "verified": True,
                    "pid": value["pid"],
                    "start_ticks": 100,
                    "scope_sha256": value["scope_sha256"],
                }
            )
            self.assertFalse(live_verify(123, 99, True))
        root_client._request.side_effect = None
        transport.mode = "live"
        attempt["mode"] = "live"
        transport._scope_client = None
        with patch("gateway_transport.os.geteuid", return_value=2005):
            with self.assertRaisesRegex(ControlRefused, "gateway_scope_required"):
                transport.exchange_reserved(attempt, grant, call, request)
        self.assertEqual(begin.call_count, 2)
        authority.roots.clear()
        transport.mode, attempt["mode"], transport._scope_client = (
            "rehearsal",
            "rehearsal",
            root_client,
        )

        def lost_send(method, raw, prefix, **kwargs):
            import json

            frame = json.loads(raw)
            authority.acquire_v2(
                2007,
                {"binding": frame["binding"], "call": frame["call"]},
                pid=123,
                start_ticks=99,
                peer_fd=read_fd,
            )
            raise OSError("lost gateway acknowledgement")

        client._send = lost_send
        with (
            patch("gateway_transport.os.geteuid", return_value=2005),
            patch("gateway_transport.time.time_ns", return_value=500_000_000),
            self.assertRaises(ControlRefused),
        ):
            transport.exchange_reserved(attempt, grant, call, request)
        self.assertEqual(authority.roots[payload_sha256(root)][2], "retired")
        self.assertIsNone(authority.roots[payload_sha256(root)][8])


if __name__ == "__main__":
    unittest.main()
