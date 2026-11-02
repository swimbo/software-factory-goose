"""Joined guard/revoke state tests; PID1, kernel, Docker and wallet are seams."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import linux_service_guard as guard
import linux_supervisor as product


class GuardLossIntegrationTests(unittest.TestCase):
    def exercise(self, *, unknown_create):
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
            product.store(
                case / "owner-scope.json",
                {"grant_sha256": product.sha(grant), "scope_sha256": "e" * 64},
            )
            if unknown_create:
                product.store(case / "start-intent.json", {"public": "fixture"})

            backend = object.__new__(product.RootSupervisor)
            backend.cfg = {"schema": 3}
            backend._case = lambda _: case
            backend._current = Mock()
            backend.prepare = Mock()
            backend.start = Mock()
            backend._kernel_scope = Mock()
            events = []

            def fence(value):
                self.assertEqual(value, grant)
                events.append("fence")

            backend._fence_execution = fence
            docker_attempts = []

            def docker(*args):
                self.assertEqual(events[-1], "fence")
                self.assertEqual(args[:2], ("container", "ls"))
                docker_attempts.append(args)
                events.append("docker")
                if len(docker_attempts) == 1:
                    raise OSError("public daemon outage")
                return b""

            backend._docker = docker
            backend.owner = Mock()
            owner_attempts = []

            def owner_revoke(scope):
                self.assertEqual(scope, "e" * 64)
                self.assertEqual(events[-1], "docker")
                owner_attempts.append(scope)
                events.append("owner")
                if len(owner_attempts) == 1:
                    raise OSError("public owner outage")

            backend.owner.revoke.side_effect = owner_revoke
            manager = Mock()
            manager.__enter__ = Mock(return_value=manager)
            manager.__exit__ = Mock(return_value=False)
            manager.snapshot.return_value = {
                "Id": intent["unit"],
                "ActiveState": "active",
                "SubState": "running",
                "MainPID": os.getpid(),
                "InvocationID": "f" * 32,
                "ControlGroup": group,
            }
            clock = {"now": 0}

            def pause(_):
                clock["now"] += 15
                if clock["now"] > 30:
                    raise AssertionError("guard retry exceeded test bound")

            with (
                patch.object(product, "RootSupervisor", return_value=backend),
                patch.object(
                    product,
                    "protected",
                    side_effect=lambda p, *a, **k: Path(p).read_bytes(),
                ),
                patch.object(product, "_ticks", return_value=400),
                patch.object(product, "_owner_alive", return_value=False),
                patch.object(guard, "_binding", return_value=binding),
                patch.object(guard, "_manager", return_value=manager),
                patch.object(guard, "_process_group", return_value=group),
                patch.object(Path, "read_text", return_value="boot"),
                patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}),
                patch.object(guard.time, "monotonic", side_effect=lambda: clock["now"]),
                patch.object(guard.time, "sleep", side_effect=pause),
            ):
                if unknown_create:
                    with self.assertRaisesRegex(
                        product.SupervisorRefused, "root_create_requires_reconciliation"
                    ):
                        guard.run_guard(
                            "public-config",
                            grant["attempt_id"],
                            binding["config_sha256"],
                        )
                else:
                    guard.run_guard(
                        "public-config", grant["attempt_id"], binding["config_sha256"]
                    )

            self.assertEqual(events[:6], ["fence", "docker", "owner"] * 2)
            self.assertEqual(len(owner_attempts), 2)
            self.assertTrue((case / "stop.json").exists())
            self.assertTrue((case / "owner-revoked.json").exists())
            self.assertFalse((case / "finished.json").exists())
            backend.prepare.assert_not_called()
            backend.start.assert_not_called()
            self.assertEqual((case / "cleanup.json").exists(), not unknown_create)
            if unknown_create:
                self.assertEqual(len(docker_attempts), 3)
                self.assertTrue((case / "start-intent.json").exists())
                backend._kernel_scope.assert_not_called()
            else:
                self.assertEqual(len(docker_attempts), 2)
                self.assertEqual(
                    json.loads((case / "cleanup.json").read_bytes()),
                    {"grant_sha256": product.sha(grant), "state": "absent"},
                )
                backend._kernel_scope.assert_called_once_with(grant, empty=True)

    def test_combined_outages_recover_only_after_fence_and_owner_ack(self):
        self.exercise(unknown_create=False)

    def test_unknown_create_stays_unresolved_after_outages_recover(self):
        self.exercise(unknown_create=True)


if __name__ == "__main__":
    unittest.main()
