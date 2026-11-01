"""Actual start-state characterization; native resources are a separate replay."""

import contextlib
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from linux_runner import recipe
import linux_supervisor as product


class StartLossStateTests(unittest.TestCase):
    def make(self, directory):
        base = Path(directory)
        case, catalog = base / "case", base / "catalog"
        case.mkdir()
        catalog.mkdir()
        attempt = {"attempt_id": "run_" + "a" * 64, "profile": "d" * 64}
        admission = {"status": "allowed"}
        grant = {
            "attempt_id": attempt["attempt_id"],
            "worker_uid": 2001,
            "broker_uid": 2005,
        }
        launch_recipe = recipe(
            suite_sha256="b" * 64,
            config_sha256="c" * 64,
            profiles={"baseline": "d" * 64, "candidate": "f" * 64},
            script_host_sha256="1" * 64,
            normalizer_sha256="2" * 64,
            broker_uid=2005,
            worker_uid=2001,
        )
        product.store(
            case / "prepare-intent.json", {"attempt": attempt, "admission": admission}
        )
        body = dict(
            grant=grant,
            prompt="public fixture",
            declarations_sha256="3" * 64,
            worker_protocol="unix-json-v1",
        )
        product.store(
            catalog / (attempt["attempt_id"] + ".launch.json"),
            dict(
                prompt_sha256=hashlib.sha256(body["prompt"].encode()).hexdigest(),
                declarations_sha256=body["declarations_sha256"],
                profile_sha256=attempt["profile"],
                max_output_tokens=1,
            ),
        )
        root = object.__new__(product.RootSupervisor)
        root.recipe, root.catalog, root.guard = launch_recipe, catalog, threading.Lock()
        root.gate = type(
            "FixtureGate", (), {"admission": staticmethod(contextlib.nullcontext)}
        )()
        root._current = (
            lambda _: case
        )  # No production admission claimed by this state test.
        root._case = lambda _: case
        return root, case, attempt, body

    def test_durable_start_intent_survives_failure_and_new_supervisor(self):
        with tempfile.TemporaryDirectory() as directory:
            root, case, attempt, body = self.make(directory)
            store = product.store

            def fail_after_intent(path, value, mode=0o600):
                if Path(path).name == "profile.json":
                    raise OSError("fixture storage failure after durable start intent")
                return store(path, value, mode)

            # Characterize the actual entry point. The fault is after its fsynced
            # intent and before any source, Docker, watchdog or inference action.
            with (
                patch.object(
                    product,
                    "protected",
                    side_effect=lambda p, *a, **k: Path(p).read_bytes(),
                ),
                patch.object(product, "store", side_effect=fail_after_intent),
            ):
                with self.assertRaisesRegex(OSError, "after durable start intent"):
                    root.start(body)
            saved = (case / "start-intent.json").read_bytes()
            self.assertEqual(json.loads(saved), body)
            self.assertFalse((case / "worker.json").exists())
            fresh = object.__new__(product.RootSupervisor)
            fresh.__dict__.update(root.__dict__)
            with (
                patch.object(
                    product,
                    "protected",
                    side_effect=lambda p, *a, **k: Path(p).read_bytes(),
                ),
                self.assertRaisesRegex(
                    product.SupervisorRefused, "root_start_already_attempted"
                ),
            ):
                fresh.start(body)
            self.assertEqual((case / "start-intent.json").read_bytes(), saved)
            result = fresh.reconcile(
                dict(attempt=attempt, record={}, recipe_sha256=product.sha(root.recipe))
            )
            self.assertEqual(result["state"], "unknown")
            self.assertEqual(
                result["receipt_sha256"],
                product.sha({k: v for k, v in result.items() if k != "receipt_sha256"}),
            )

    def test_cleanup_receipt_cannot_rearm_a_prior_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root, case, attempt, body = self.make(directory)
            product.store(case / "start-intent.json", body)
            product.store(
                case / "cleanup.json",
                {"grant_sha256": product.sha(body["grant"]), "state": "absent"},
            )
            with (
                patch.object(
                    product,
                    "protected",
                    side_effect=lambda p, *a, **k: Path(p).read_bytes(),
                ),
                self.assertRaisesRegex(
                    product.SupervisorRefused, "root_start_already_attempted"
                ),
            ):
                root.start(body)
            self.assertEqual(
                root.reconcile(
                    dict(
                        attempt=attempt,
                        record={},
                        recipe_sha256=product.sha(root.recipe),
                    )
                )["state"],
                "unknown",
            )


if __name__ == "__main__":
    unittest.main()
