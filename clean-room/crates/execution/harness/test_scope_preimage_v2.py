"""Public fixtures for a read-only wallet-scope preimage, not live admission."""

import copy
import contextlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import linux_supervisor as product
import linux_runner


def legacy_scope():
    # The digest below is the wallet's frozen Rust serde_json test vector.
    return {
        "task": "task",
        "attempt": 1,
        "generation": "generation",
        "worker": "worker",
        "lease_sha256": "d" * 64,
        "issued_at_ms": 100,
        "expires_at_ms": 172800000,
        "route": {
            "route_sha256": "e" * 64,
            "review_sha256": "f" * 64,
            "valid_from_ms": 100,
            "valid_until_ms": 172800000,
            "max_request_bytes": 65536,
            "max_output_tokens": 100,
            "components": [
                {"id": "classifier", "max_charge_microusd": 100000},
                {"id": "answer", "max_charge_microusd": 200000},
            ],
        },
    }


class ScopePreimageTests(unittest.TestCase):
    def test_scope_read_client_remains_broker_only(self):
        client = object.__new__(linux_runner.PrivateRootSupervisorClient)
        client.broker_uid = 2005
        client._request = Mock(return_value={"schema": 2})
        with patch.object(linux_runner.os, "geteuid", return_value=2001):
            with self.assertRaises(linux_runner.LinuxRunnerRefused):
                client("scope_preimage_v2", {})
        client._request.assert_not_called()
        with patch.object(linux_runner.os, "geteuid", return_value=2005):
            self.assertEqual(client("scope_preimage_v2", {}), {"schema": 2})
        client._request.assert_called_once_with("/harness-launch/scope_preimage_v2", {})

    def test_legacy_rust_digest_and_optional_null(self):
        value = legacy_scope()
        expected = "fbba1cce5b33e3a6fbe52dffd6b04f1b586ba9c9f183d9e04bd8ab93ce8229a7"
        self.assertEqual(product.factory_scope_digest(value), expected)
        value["route"]["usage_tariff_sha256"] = None
        self.assertEqual(product.factory_scope_digest(value), expected)

    def test_rated_rust_digest(self):
        value = legacy_scope()
        value["route"]["usage_tariff_sha256"] = "a" * 64
        self.assertEqual(
            product.factory_scope_digest(value),
            "a90e0900014ee1acd203ffc03f142cc4043005045b39a7f813f3b5f5ec017b54",
        )

    def test_reordered_object_keys_hash_the_same_but_components_are_ordered(self):
        value = legacy_scope()
        reordered = dict(reversed(list(value.items())))
        reordered["route"] = dict(reversed(list(value["route"].items())))
        self.assertEqual(
            product.factory_scope_digest(value), product.factory_scope_digest(reordered)
        )
        reordered["route"]["components"] = list(reversed(value["route"]["components"]))
        self.assertNotEqual(
            product.factory_scope_digest(value), product.factory_scope_digest(reordered)
        )

    def test_unknown_fields_and_non_wallet_types_are_rejected(self):
        for change in (
            "extra",
            "boolean",
            "negative",
            "overflow",
            "invalid_id",
            "duplicate_component",
        ):
            value = copy.deepcopy(legacy_scope())
            if change == "extra":
                value["route"]["unreviewed"] = 1
            if change == "boolean":
                value["attempt"] = True
            if change == "negative":
                value["route"]["max_output_tokens"] = -1
            if change == "overflow":
                value["route"]["components"][0]["max_charge_microusd"] = 2**64
            if change == "invalid_id":
                value["worker"] = "untrusted key"
            if change == "duplicate_component":
                value["route"]["components"][1]["id"] = "classifier"
            with (
                self.subTest(change=change),
                self.assertRaises(product.SupervisorRefused),
            ):
                product.factory_scope_digest(value)

    def test_root_returns_only_current_wallet_acknowledged_scope_without_mutation(self):
        scope = legacy_scope()
        digest = product.factory_scope_digest(scope)
        attempt = {"attempt_id": "run_" + "a" * 64}
        grant = {"attempt_id": attempt["attempt_id"], "public": "grant"}
        admission = {"status": "allowed"}
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            (case / "grant.json").write_text(json.dumps(grant))
            (case / "prepare-intent.json").write_text(
                json.dumps({"attempt": attempt, "admission": admission})
            )
            backend = object.__new__(product.RootSupervisor)
            backend._case = lambda _: case
            backend._current = Mock(return_value=case)
            backend._saved_scope = Mock(return_value=digest)
            backend._catalog = Mock(
                return_value=({"scope": scope, "scope_sha256": digest}, {})
            )
            backend.owner = Mock()
            backend.gate = type(
                "FixtureGate", (), {"admission": staticmethod(contextlib.nullcontext)}
            )()
            backend.guard = threading.RLock()
            with (
                patch.object(
                    product,
                    "protected",
                    side_effect=lambda p, *a, **k: Path(p).read_bytes(),
                ),
                patch.object(product.time, "time_ns", return_value=100_000_000),
            ):
                reply = backend.scope_preimage_v2(
                    {"attempt": attempt, "scope_sha256": digest}
                )
                self.assertEqual(
                    reply, {"schema": 2, "scope_sha256": digest, "scope": scope}
                )
                reply["scope"]["worker"] = "changed"
                self.assertEqual(scope["worker"], "worker")
                for marker in ("owner-revoked.json", "finished.json"):
                    path = case / marker
                    path.write_text("{}")
                    with (
                        self.subTest(marker=marker),
                        self.assertRaises(product.SupervisorRefused),
                    ):
                        backend.scope_preimage_v2(
                            {"attempt": attempt, "scope_sha256": digest}
                        )
                    path.unlink()
                for now_ms in (99, 172800000):
                    with (
                        self.subTest(now_ms=now_ms),
                        patch.object(
                            product.time, "time_ns", return_value=now_ms * 1_000_000
                        ),
                        self.assertRaises(product.SupervisorRefused),
                    ):
                        backend.scope_preimage_v2(
                            {"attempt": attempt, "scope_sha256": digest}
                        )
                for body in (
                    {"attempt": attempt, "scope_sha256": "a" * 64},
                    {
                        "attempt": {
                            "attempt_id": attempt["attempt_id"],
                            "changed": True,
                        },
                        "scope_sha256": digest,
                    },
                    {"attempt": attempt, "scope_sha256": digest, "extra": 1},
                ):
                    with self.assertRaises(product.SupervisorRefused):
                        backend.scope_preimage_v2(body)
                backend._saved_scope.return_value = "c" * 64
                with self.assertRaises(product.SupervisorRefused):
                    backend.scope_preimage_v2(
                        {"attempt": attempt, "scope_sha256": digest}
                    )
                backend._saved_scope.return_value = digest
                backend._catalog.return_value = (
                    {"scope": scope | {"worker": "other"}, "scope_sha256": digest},
                    {},
                )
                with self.assertRaises(product.SupervisorRefused):
                    backend.scope_preimage_v2(
                        {"attempt": attempt, "scope_sha256": digest}
                    )
                backend._catalog.return_value = (
                    {"scope": scope, "scope_sha256": digest},
                    {},
                )
                backend._current.side_effect = product.SupervisorRefused("expired")
                with self.assertRaises(product.SupervisorRefused):
                    backend.scope_preimage_v2(
                        {"attempt": attempt, "scope_sha256": digest}
                    )
            self.assertEqual(backend.owner.mock_calls, [])


if __name__ == "__main__":
    unittest.main()
