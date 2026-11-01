"""State/protocol proofs; these tests do not impersonate protected Linux peers."""

import base64
import threading
import unittest
from unittest.mock import patch

from gateway_custody import (
    ProtectedGatewayAcquisitionAuthority,
    PrivateCaptureOpenClient,
)
from gateway_transport import PrivateGatewayClient, ProtectedGatewayTransport
from protected_spending_control import (
    ControlRefused,
    PrivateSpendingClient,
    binding_digest,
)
from test_protected_spending_control import body
from test_rated_control import rated_fixture


class GatewayTransportTests(unittest.TestCase):
    def setUp(self):
        identity = patch("gateway_transport.os.geteuid", return_value=2005)
        identity.start()
        self.addCleanup(identity.stop)

    def setup_transport(self):
        control, attempt, events, launch, collector = rated_fixture()
        begun = set()

        class SingleUseJournal:
            def __call__(self, method, call):
                events.append(method)
                if method == "reserve":
                    return "Reserved"
                if method != "begin" or call["call_id"] in begun:
                    return False
                begun.add(call["call_id"])
                return True

        broker = control.rpc = SingleUseJournal()

        # Only the state machine is instantiated here. Actual private constructors
        # require Linux identities/listeners and are a separate native proof.
        authority = object.__new__(ProtectedGatewayAcquisitionAuthority)
        authority.journal = broker
        authority.protected_uid = 2005
        authority.uid = 2007
        authority.roots, authority.lock = {}, threading.RLock()
        authority.begin = lambda call: broker("begin", call)
        authority.open_capture = lambda root: {
            "root_sha256": binding_digest(root),
            "opened": True,
        }
        client = object.__new__(PrivateGatewayClient)
        client.owner, client.service_uid, client.broker_uid = "owner", 2007, 2005

        def send(method, raw, prefix, **limits):
            import json

            request = json.loads(raw)
            self.assertEqual((method, prefix), ("exchange", "/gateway/"))
            authority.acquire(2007, {k: request[k] for k in ("binding", "call")})
            events.append("gateway_exchange")
            return {
                **{
                    k: request["call"][k]
                    for k in ("call_id", "scope_sha256", "request_sha256")
                },
                "physical_manifest_sha256": "5" * 64,
                "sse": base64.b64encode(b"data: [DONE]\n\n").decode(),
            }

        client._send = send
        transport = object.__new__(ProtectedGatewayTransport)
        transport.journal, transport.acquisition, transport.client = (
            broker,
            authority,
            client,
        )
        transport.owner, transport.route, transport.tariff, transport.mode = (
            "owner",
            control.config["route_sha256"],
            control.config["tariff_sha256"],
            "rehearsal",
        )
        control.provider = transport
        return control, attempt, events, authority, client

    def test_gateway_path_consumes_begin_once_and_collects_before_return(self):
        control, attempt, events, _, _ = self.setup_transport()
        control.admit(attempt)
        result = control.exchange(attempt, body(), 0)
        self.assertEqual(result["sse"], b"data: [DONE]\n\n")
        self.assertEqual(
            events,
            ["admit", "reserve", "begin", "gateway_exchange", "collector"],
        )

    def test_unknown_gateway_ack_cannot_rearm_or_resend(self):
        control, attempt, events, authority, client = self.setup_transport()
        original = client._send

        def lose(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("discarded gateway reply")

        client._send = lose
        control.admit(attempt)
        for _ in range(2):
            with self.assertRaises(ControlRefused):
                control.exchange(attempt, body(), 0)
        self.assertEqual(events.count("begin"), 1)
        self.assertEqual(events.count("gateway_exchange"), 1)
        self.assertNotIn("collector", events)
        self.assertEqual(len(authority.roots), 1)

    def test_request_tampering_and_expiry_never_arm(self):
        control, attempt, _, authority, _ = self.setup_transport()
        control.admit(attempt)
        grant = control.states[attempt["attempt_id"]]["grant"]
        request = body()
        call = dict(
            call_id="call",
            scope_sha256=grant["scope_sha256"],
            request_sha256=binding_digest(request),
            sequence=0,
            request_bytes=len(
                __import__("factory_harness").canonical(request).encode()
            ),
            output_tokens=request["max_tokens"],
        )
        for changed in (
            call | {"request_sha256": "0" * 64},
            call | {"request_bytes": 1},
        ):
            with self.assertRaises(ControlRefused):
                control.provider.exchange_reserved(attempt, grant, changed, request)
        with self.assertRaises(ControlRefused):
            control.provider.exchange_reserved(
                attempt, grant | {"expires_at_ms": 1}, call, request
            )
        self.assertEqual(authority.roots, {})

    def test_response_content_requires_exact_complete_bound_receipt(self):
        for change in (
            {"scope_sha256": "0" * 64},
            {"sse": "!!!"},
            {"extra": "unreviewed provider data"},
        ):
            control, attempt, events, _, client = self.setup_transport()
            send = client._send
            client._send = lambda *a, **k: send(*a, **k) | change
            control.admit(attempt)
            with self.subTest(change=change), self.assertRaises(ControlRefused):
                control.exchange(attempt, body(), 0)
            self.assertNotIn("collector", events)

    def test_caller_property_does_not_select_gateway_authority(self):
        control, attempt, events, *_ = rated_fixture()
        control.provider.gateway_owned = True
        control.admit(attempt)
        control.exchange(attempt, body(), 0)
        self.assertEqual(events[:4], ["admit", "reserve", "begin", "provider"])

    def test_composition_refuses_different_money_owner_or_peer_roles(self):
        # Metadata composition only; bypassing socket constructors does not
        # establish kernel identity. The native protocol replay proves that part.
        journal = object.__new__(PrivateSpendingClient)
        journal.owner, journal.broker_uid, journal.service_uid = "owner", 2005, 2004
        capture = object.__new__(PrivateCaptureOpenClient)
        capture.owner, capture.broker_uid, capture.service_uid = "owner", 2005, 2008
        authority = ProtectedGatewayAcquisitionAuthority(
            journal, capture, gateway_uid=2007
        )
        client = object.__new__(PrivateGatewayClient)
        client.owner, client.broker_uid, client.service_uid = "owner", 2005, 2007
        options = dict(route_sha256="a" * 64, tariff_sha256="b" * 64, mode="rehearsal")
        ProtectedGatewayTransport(journal, authority, client, **options)
        other = object.__new__(PrivateSpendingClient)
        other.__dict__.update(journal.__dict__)
        with self.assertRaises(ControlRefused):
            ProtectedGatewayTransport(other, authority, client, **options)
        for field, value in (
            ("owner", "other"),
            ("broker_uid", 2001),
            ("service_uid", 2008),
        ):
            old = getattr(client, field)
            setattr(client, field, value)
            with self.subTest(field=field), self.assertRaises(ControlRefused):
                ProtectedGatewayTransport(journal, authority, client, **options)
            setattr(client, field, old)
        for field in ("route_sha256", "tariff_sha256", "mode"):
            with self.subTest(field=field), self.assertRaises(ControlRefused):
                ProtectedGatewayTransport(
                    journal, authority, client, **(options | {field: "invalid"})
                )
        with patch("gateway_transport.os.geteuid", return_value=2007):
            with self.assertRaises(ControlRefused):
                ProtectedGatewayTransport(journal, authority, client, **options)

    def test_gateway_deadline_cannot_cross_the_reserved_utc_day(self):
        control, attempt, _, _, client = self.setup_transport()
        control.admit(attempt)
        sent = []
        send = client._send

        def record(method, raw, prefix, **limits):
            import json

            sent.append(json.loads(raw)["expires_at_ms"])
            return send(method, raw, prefix, **limits)

        day_end = 20000 * 86400000
        client._send = record
        with patch(
            "gateway_transport.time.time_ns", return_value=(day_end - 50) * 1000000
        ):
            control.exchange(attempt, body(), 0)
        self.assertEqual(sent, [day_end])


if __name__ == "__main__":
    unittest.main()
