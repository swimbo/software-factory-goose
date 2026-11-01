"""Real durable capture transactions; no provider or launch authority fixtures."""

import copy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from gateway_custody import CaptureStore, GatewayAcquisitionAuthority, root_binding
from physical_usage import payload_sha256
from protected_spending_control import ControlRefused
from test_physical_usage import fixture
from usage_rating import TariffCard, TariffRate


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.binding, self.profile, self.envelope = fixture()
        self.binding = replace(self.binding, owner="owner")
        self.tariff = TariffCard(
            "1",
            "constant_peak",
            "https://example.org/pricing",
            "b" * 64,
            1,
            1,
            100000,
            (
                TariffRate(
                    "provider",
                    "model",
                    "0.0000001",
                    "0.0000001",
                    "0.0000001",
                    "0.0000002",
                    "0",
                ),
            ),
        )
        self.binding = replace(self.binding, tariff_sha256=self.tariff.sha256())
        self.envelope["binding"] = self.binding.as_dict()
        self.path = Path(self.temp.name) / "capture.db"

    def store(self):
        return CaptureStore(
            self.path,
            owner="owner",
            route_sha256=self.binding.route_sha256,
            tariff=self.tariff,
            profiles=(self.profile,),
            components=("answer", "fallback"),
            broker_uid=2005,
            gateway_uid=2007,
            collector_uid=2006,
        )

    def test_closed_data_requires_acquired_open_and_survives_restart(self):
        with self.store() as store:
            with self.assertRaises(ControlRefused):
                store.dispatch(2007, "close", self.envelope)
            root = root_binding(self.binding.as_dict())
            self.assertEqual(
                store.dispatch(2005, "open", root),
                {"root_sha256": payload_sha256(root), "opened": True},
            )
            self.assertEqual(
                store.dispatch(2007, "close", self.envelope),
                {
                    "physical_manifest_sha256": self.binding.physical_manifest_sha256,
                    "stored": True,
                },
            )
        with self.store() as store:
            self.assertEqual(
                store.dispatch(2006, "closed", self.binding.as_dict()), self.envelope
            )
            changed = copy.deepcopy(self.envelope)
            changed["snapshot"]["calls"][0]["usage"]["private"] = 1
            with self.assertRaises(Exception):
                store.dispatch(2007, "close", changed)
            self.assertEqual(
                store.dispatch(2006, "closed", self.binding.as_dict()), self.envelope
            )

    def test_dispatch_role_matrix_rejects_cross_role_and_worker(self):
        with self.store() as store:
            for uid in (0, 2001, 2005, 2006, 2007):
                for method in ("open", "close", "closed", "audit"):
                    if (uid, method) in (
                        (2005, "open"),
                        (2007, "close"),
                        (2006, "closed"),
                        (2006, "audit"),
                    ):
                        continue
                    with self.assertRaises(ControlRefused):
                        store.dispatch(uid, method, {})

    def test_root_acquisition_is_one_use_and_unknown_is_never_rearmed(self):
        root = root_binding(self.binding.as_dict())
        call = dict(
            call_id=root["call_id"],
            scope_sha256=root["scope_sha256"],
            request_sha256=root["request_sha256"],
            sequence=0,
            request_bytes=100,
            output_tokens=10,
        )
        begin = Mock(return_value=True)
        opened = Mock(
            return_value={"root_sha256": payload_sha256(root), "opened": True}
        )
        authority = GatewayAcquisitionAuthority(begin, opened, gateway_uid=2007)
        authority.arm(root, call)
        body = {"binding": root, "call": call}
        self.assertEqual(
            authority.acquire(2007, body),
            {"root_sha256": payload_sha256(root), "acquired": True},
        )
        with self.assertRaises(ControlRefused):
            authority.acquire(2007, body)
        self.assertEqual(begin.call_count, 1)
        unknown = GatewayAcquisitionAuthority(
            begin, Mock(side_effect=OSError("lost open ack")), gateway_uid=2007
        )
        unknown.arm(root, call)
        for _ in range(2):
            with self.assertRaises(ControlRefused):
                unknown.acquire(2007, body)
        self.assertEqual(begin.call_count, 2)
        with self.assertRaises(ControlRefused):
            unknown.arm(root, call)

    def test_audit_is_exact_recalculation_and_invalid_payload_never_persists(self):
        from physical_usage import normalize_capture
        from usage_rating import UsageRatedCollector

        manifest, usages, _, _ = normalize_capture(
            self.envelope, self.binding, (self.profile,), ("answer", "fallback")
        )
        report = UsageRatedCollector(
            self.tariff, self.tariff.sha256(), lambda c: usages[c.call_id]
        ).collect(manifest)
        self.assertEqual(report["usage_rated_microusd"], 2)
        report["capture_sha256"] = self.binding.physical_manifest_sha256
        report["usage_schema_profiles"] = [self.profile.as_dict()]
        report.pop("audit_sha256")
        report["audit_sha256"] = payload_sha256(report)
        with self.store() as store:
            store.dispatch(2005, "open", root_binding(self.binding.as_dict()))
            store.dispatch(2007, "close", self.envelope)
            bad = copy.deepcopy(report)
            bad["secret"] = "never persist this field"
            bad.pop("audit_sha256")
            bad["audit_sha256"] = payload_sha256(bad)
            with self.assertRaises(ControlRefused):
                store.dispatch(
                    2006, "audit", {"binding": self.binding.as_dict(), "audit": bad}
                )
            self.assertIsNone(store.db.execute("SELECT audit FROM roots").fetchone()[0])
            ack = store.dispatch(
                2006, "audit", {"binding": self.binding.as_dict(), "audit": report}
            )
            self.assertEqual(
                ack, {"audit_sha256": report["audit_sha256"], "stored": True}
            )
            self.assertEqual(
                store.dispatch(
                    2006, "audit", {"binding": self.binding.as_dict(), "audit": report}
                ),
                ack,
            )
        with self.store() as store:
            self.assertEqual(
                store.db.execute("SELECT audit FROM roots").fetchone()[0],
                __import__("factory_harness").canonical(report),
            )

    def test_racing_acquisitions_and_lost_begin_ack_never_open_twice(self):
        from concurrent.futures import ThreadPoolExecutor

        root = root_binding(self.binding.as_dict())
        call = dict(
            call_id=root["call_id"],
            scope_sha256=root["scope_sha256"],
            request_sha256=root["request_sha256"],
            sequence=0,
            request_bytes=100,
            output_tokens=10,
        )
        begin = Mock(return_value=True)
        opened = Mock(
            return_value={"root_sha256": payload_sha256(root), "opened": True}
        )
        authority = GatewayAcquisitionAuthority(begin, opened, gateway_uid=2007)
        authority.arm(root, call)

        def acquire(_):
            try:
                return authority.acquire(2007, {"binding": root, "call": call})[
                    "acquired"
                ]
            except ControlRefused:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(acquire, range(2))), 1)
        self.assertEqual(begin.call_count, 1)
        self.assertEqual(opened.call_count, 1)
        lost = GatewayAcquisitionAuthority(
            Mock(side_effect=OSError("ack lost")), opened, gateway_uid=2007
        )
        lost.arm(root, call)
        for _ in range(2):
            with self.assertRaises(ControlRefused):
                lost.acquire(2007, {"binding": root, "call": call})
        self.assertEqual(opened.call_count, 1)

    def test_storage_exhaustion_and_policy_drift_do_not_create_new_authority(self):
        from unittest.mock import patch

        with self.store() as store:
            with patch("gateway_custody.MAX_STORAGE", 1):
                with self.assertRaises(ControlRefused):
                    store.dispatch(2005, "open", root_binding(self.binding.as_dict()))
            self.assertEqual(
                store.db.execute("SELECT count(*) FROM roots").fetchone()[0], 0
            )
        altered = replace(self.profile, review_sha256="e" * 64)
        with self.assertRaises(ControlRefused):
            CaptureStore(
                self.path,
                owner="owner",
                route_sha256=self.binding.route_sha256,
                tariff=self.tariff,
                profiles=(altered,),
                components=("answer", "fallback"),
                broker_uid=2005,
                gateway_uid=2007,
                collector_uid=2006,
            )


if __name__ == "__main__":
    unittest.main()
