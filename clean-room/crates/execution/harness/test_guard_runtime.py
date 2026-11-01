"""Actual guard loop/state; kernel, PID1 and wallet are explicit test seams."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import linux_service_guard as guard
import linux_supervisor as product


class GuardRuntimeTests(unittest.TestCase):
    def exercise(self, *, cleanup=False, drift=False, expiry=False, exhausted=False):
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary)
            grant = {"attempt_id": "run_" + "a" * 64, "boot_id": "boot"}
            binding = {
                "config_sha256": "b" * 64,
                "guard_sha256": "c" * 64,
                "supervisor_sha256": "d" * 64,
            }
            group = "/system.slice/" + guard.unit_name(grant)
            intent = dict(
                schema=1,
                grant_sha256=product.sha(grant),
                **binding,
                unit=guard.unit_name(grant),
                owner_pid=100,
                owner_ticks=200,
                owner_cgroup="/system.slice/owner.service",
                worker_cgroup="/worker.slice",
                boot_id="boot",
            )
            product.store(case / "grant.json", grant)
            product.store(case / "guard-intent.json", intent)
            backend = Mock()
            backend._case.return_value = case
            backend._current.side_effect = (
                [None, guard.GuardRefused("expired")] if expiry else None
            )
            manager = Mock()
            manager.__enter__ = Mock(return_value=manager)
            manager.__exit__ = Mock(return_value=False)
            manager.snapshot.return_value = {
                "Id": intent["unit"],
                "ActiveState": "active",
                "SubState": "running",
                "MainPID": 0 if cleanup else os.getpid(),
                "InvocationID": "f" * 32,
                "ControlGroup": group,
            }
            bindings = []

            def read_binding(_):
                bindings.append(len(bindings))
                if len(bindings) > 1:
                    self.assertTrue((case / "guard-ready.json").exists())
                    if drift:
                        return binding | {"guard_sha256": "e" * 64}
                return binding

            attempts = []

            def revoke(value):
                self.assertEqual(value, {"grant": grant})
                attempts.append(value)
                if exhausted or len(attempts) == 1:
                    raise OSError("administrative acknowledgement unavailable")
                product.store(
                    case / "revocation-ack.json", {"grant_sha256": product.sha(grant)}
                )

            backend.revoke.side_effect = revoke
            sleeps = []

            def pause(duration):
                sleeps.append(duration)
                # An unfenced loop must fail deterministically, never hang CI.
                if len(sleeps) > 2:
                    raise AssertionError("guard failed to intervene")

            clock = Mock(side_effect=[0, 30]) if exhausted else Mock(return_value=0)
            failure = None
            with (
                patch.object(
                    product, "RootSupervisor", return_value=backend
                ) as constructor,
                patch.object(
                    product,
                    "protected",
                    side_effect=lambda p, *a, **k: Path(p).read_bytes(),
                ),
                patch.object(product, "_ticks", return_value=400),
                patch.object(product, "_owner_alive", return_value=True),
                patch.object(guard, "_binding", side_effect=read_binding),
                patch.object(guard, "_manager", return_value=manager),
                patch.object(guard, "_process_group", return_value=group),
                patch.object(Path, "read_text", return_value="boot"),
                patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}),
                patch.object(guard.time, "monotonic", clock),
                patch.object(guard.time, "sleep", side_effect=pause),
            ):
                try:
                    guard.run_guard(
                        "public-config",
                        grant["attempt_id"],
                        binding["config_sha256"],
                        cleanup=cleanup,
                    )
                except Exception as error:
                    failure = error
                constructor.assert_called_once_with("public-config", cleanup_only=True)
            backend.prepare.assert_not_called()
            backend.start.assert_not_called()
            self.assertFalse((case / "finished.json").exists())
            ready = (
                json.loads((case / "guard-ready.json").read_bytes())
                if (case / "guard-ready.json").exists()
                else None
            )
            return {
                "failure": failure,
                "attempts": len(attempts),
                "ack": (case / "revocation-ack.json").exists(),
                "ready": ready,
                "binding": binding,
                "current_checks": backend._current.call_count,
                "sleeps": sleeps,
            }

    def test_source_drift_after_readiness_retries_revocation_without_reconstruction(
        self,
    ):
        state = self.exercise(drift=True)
        self.assertIsNone(state["failure"])
        self.assertEqual(state["attempts"], 2)
        self.assertTrue(state["ack"])
        self.assertEqual(
            state["ready"]["guard_sha256"], state["binding"]["guard_sha256"]
        )
        self.assertEqual(state["current_checks"], 1)

    def test_lease_expiry_intervenes_even_while_owner_remains_alive(self):
        state = self.exercise(expiry=True)
        self.assertIsNone(state["failure"])
        self.assertEqual(state["current_checks"], 2)
        self.assertEqual(state["attempts"], 2)
        self.assertTrue(state["ack"])

    def test_monitor_retry_deadline_preserves_unknown_without_completion(self):
        state = self.exercise(drift=True, exhausted=True)
        self.assertIsInstance(state["failure"], OSError)
        self.assertEqual(state["attempts"], 1)
        self.assertFalse(state["ack"])
        self.assertEqual(state["sleeps"], [])

    def test_stop_post_retries_only_revocation_and_obeys_its_deadline(self):
        for exhausted in (False, True):
            with self.subTest(exhausted=exhausted):
                state = self.exercise(cleanup=True, exhausted=exhausted)
                self.assertIsNone(state["ready"])
                self.assertEqual(state["current_checks"], 0)
                self.assertEqual(state["attempts"], 1 if exhausted else 2)
                self.assertEqual(state["ack"], not exhausted)
                if exhausted:
                    self.assertIsInstance(state["failure"], OSError)
                else:
                    self.assertIsNone(state["failure"])
