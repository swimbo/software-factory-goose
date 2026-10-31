import unittest
from linux_supervisor import (
    docker_arguments,
    validate_catalog,
    SupervisorRefused,
    WORKER_IMAGE,
)
from linux_runner import recipe
from linux_goose_runtime import LINUX_GOOSE_SHA256
from protected_goose_runtime import sha


class SupervisorContractTests(unittest.TestCase):
    def setUp(self):
        self.attempt = dict(
            attempt_id="run_" + "a" * 64,
            task_id="task",
            suite_sha256="b" * 64,
            config_sha256="c" * 64,
            goose_build=LINUX_GOOSE_SHA256,
            variant="baseline",
            profile="d" * 64,
            model="auto",
            route="e" * 64,
            budget=750000,
            daily_cap=5000000,
            mode="live",
        )
        self.recipe = recipe(
            suite_sha256="b" * 64,
            config_sha256="c" * 64,
            profiles={"baseline": "d" * 64, "candidate": "f" * 64},
            script_host_sha256="1" * 64,
            normalizer_sha256="2" * 64,
            broker_uid=2005,
            worker_uid=2001,
        )
        self.admission = dict(
            attempt_id=self.attempt["attempt_id"],
            status="allowed",
            authority_receipt_sha256="3" * 64,
        )
        self.scope = dict(
            task="01K00000000000000000000001",
            attempt=1,
            generation="01K00000000000000000000000",
            worker="worker",
            lease_sha256="4" * 64,
            issued_at_ms=1000,
            expires_at_ms=181000,
            route={"route_sha256": "e" * 64},
        )
        self.entry = dict(
            schema=1,
            attempt=self.attempt,
            admission_sha256=sha(self.admission),
            recipe_sha256=sha(self.recipe),
            scope=self.scope,
            factory_task_id="01K00000000000000000000001",
            scope_sha256="5" * 64,
            cgroup={
                "path": "/sys/fs/cgroup/sfactoryharness" + "a" * 64 + ".slice",
                "dev": 1,
                "ino": 2,
                "boot_id": "11111111-1111-4111-8111-111111111111",
            },
        )
        self.entry["control_grant"] = dict(
            status="allowed",
            attempt_id=self.attempt["attempt_id"],
            attempt_sha256=sha(self.attempt),
            scope_sha256="5" * 64,
            policy_sha256="6" * 64,
            owner="benchmark",
            route_sha256="e" * 64,
            expires_at_ms=181000,
            authority_receipt_sha256="3" * 64,
        )
        self.lease = dict(
            schema=1,
            attempt_sha256=sha(self.attempt),
            task="01K00000000000000000000001",
            generation="01K00000000000000000000000",
            worker="worker",
            lease_sha256="4" * 64,
            issued_at_ms=1000,
            expires_at_ms=181000,
            boot_id=self.entry["cgroup"]["boot_id"],
        )

    def test_catalog_requires_exact_frozen_scope_and_current_lease(self):
        self.assertEqual(
            validate_catalog(
                self.entry,
                self.lease,
                self.attempt,
                self.admission,
                self.recipe,
                now_ms=1001,
            ),
            self.entry,
        )
        for changes in (
            {"attempt_sha256": "0" * 64},
            {"lease_sha256": "0" * 64},
            {"expires_at_ms": 1001},
            {"worker": "other"},
        ):
            with self.assertRaises(SupervisorRefused):
                validate_catalog(
                    self.entry,
                    self.lease | changes,
                    self.attempt,
                    self.admission,
                    self.recipe,
                    now_ms=1001,
                )
        with self.assertRaises(SupervisorRefused):
            validate_catalog(
                self.entry | {"scope": self.scope | {"task": "other"}},
                self.lease,
                self.attempt,
                self.admission,
                self.recipe,
                now_ms=1001,
            )

    def test_frozen_worker_command_has_no_worktree_key_docker_or_evaluator_mount(self):
        grant = {
            "attempt_id": self.attempt["attempt_id"],
            "grant_id": "6" * 64,
            "cgroup_path": self.entry["cgroup"]["path"],
            "worker_uid": 2001,
        }
        args = docker_arguments(
            grant,
            goose="/var/lib/sfactory-harness/state/"
            + self.attempt["attempt_id"]
            + "/mounts/goose",
            worker="/var/lib/sfactory-harness/state/"
            + self.attempt["attempt_id"]
            + "/mounts/worker",
            profile="/var/lib/sfactory-harness/state/"
            + self.attempt["attempt_id"]
            + "/mounts/profile",
            goose_profile="/var/lib/sfactory-harness/state/"
            + self.attempt["attempt_id"]
            + "/mounts/goose_profile",
            prompt="/var/lib/sfactory-harness/state/"
            + self.attempt["attempt_id"]
            + "/mounts/prompt",
            relay="/var/lib/sfactory-harness/state/"
            + self.attempt["attempt_id"]
            + "/mounts/relay",
        )
        self.assertEqual(
            args[-4:],
            [
                WORKER_IMAGE,
                "-I",
                "-B",
                "/factory/linux_worker.py",
            ],
        )
        self.assertIn("--read-only", args)
        self.assertIn("none", args)
        self.assertIn("ALL", args)
        mounts = [args[i + 1] for i, a in enumerate(args) if a == "--mount"]
        self.assertEqual(len(mounts), 6)
        self.assertTrue(all(m.endswith(",readonly") for m in mounts))
        self.assertFalse(
            any(
                x in " ".join(args)
                for x in ("docker.sock", "workspace", "evaluation", "credential")
            )
        )
        with self.assertRaises(SupervisorRefused):
            docker_arguments(
                grant | {"worker_uid": 0},
                goose="/x",
                worker="/x",
                profile="/x",
                goose_profile="/x",
                prompt="/x",
                relay="/x",
            )


class PermanentTaskMappingTests(unittest.TestCase):
    def test_all_six_attempts_share_one_factory_task_and_tasks_are_distinct(self):
        from linux_supervisor import validate_catalog_manifest
        import hashlib

        slots = []
        for i in range(20):
            for repeat in range(3):
                for variant in ("baseline", "candidate"):
                    value = f"{i}:{repeat}:{variant}"
                    slots.append(
                        dict(
                            attempt_id="run_"
                            + hashlib.sha256(value.encode()).hexdigest(),
                            attempt_sha256=hashlib.sha256(
                                ("attempt:" + value).encode()
                            ).hexdigest(),
                            task_id="task" + str(i),
                            factory_task_id="01K" + str(i).zfill(23),
                            repeat=repeat,
                            variant=variant,
                        )
                    )
        manifest = dict(
            schema=1, suite_sha256="b" * 64, config_sha256="c" * 64, attempts=slots
        )
        self.assertEqual(
            len(validate_catalog_manifest(manifest, "b" * 64, "c" * 64)), 120
        )
        import copy

        for index, factory in (
            (1, "01K" + str(99).zfill(23)),
            (6, slots[0]["factory_task_id"]),
        ):
            changed = copy.deepcopy(manifest)
            changed["attempts"][index]["factory_task_id"] = factory
            with self.assertRaises(SupervisorRefused):
                validate_catalog_manifest(changed, "b" * 64, "c" * 64)


class CleanupOutcomeTests(unittest.TestCase):
    def make(self, directory):
        from linux_supervisor import RootSupervisor
        from unittest.mock import Mock
        from pathlib import Path

        root = object.__new__(RootSupervisor)
        case = Path(directory)
        root._saved = Mock(return_value=case)
        root._docker = Mock(return_value=b"")
        root._kernel_scope = Mock()
        return root, case, {"attempt_id": "run_" + "a" * 64, "grant_id": "b" * 64}

    def test_known_removed_container_cleanup_is_idempotent(self):
        import tempfile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as d:
            root, case, grant = self.make(d)
            (case / "start-intent.json").write_text("{}")
            (case / "container.json").write_text("{}")
            mounts = case / "mounts"
            mounts.mkdir()
            for name in (
                "goose",
                "worker",
                "profile",
                "goose_profile",
                "prompt",
                "relay",
            ):
                (mounts / name).write_text("owned fixture")
            with patch(
                "linux_supervisor.protected",
                side_effect=lambda p, *a, **k: p.read_bytes(),
            ):
                root._cleanup(grant)
                root._cleanup(grant)
            self.assertFalse(mounts.exists())
            self.assertEqual(root._docker.call_count, 2)
            self.assertTrue(
                all(call.args[0] == "container" for call in root._docker.call_args_list)
            )
            self.assertEqual(root._kernel_scope.call_count, 2)

    def test_unacknowledged_create_absence_is_not_success(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            root, case, grant = self.make(d)
            (case / "start-intent.json").write_text("{}")
            mounts = case / "mounts"
            mounts.mkdir()
            (mounts / "goose").write_text("retain on unknown")
            with self.assertRaisesRegex(
                SupervisorRefused, "root_create_requires_reconciliation"
            ):
                root._cleanup(grant)
            self.assertFalse((case / "cleanup.json").exists())
            self.assertEqual((mounts / "goose").read_text(), "retain on unknown")

    def test_daemon_failure_is_not_absence(self):
        import tempfile
        import subprocess

        with tempfile.TemporaryDirectory() as d:
            root, case, grant = self.make(d)
            root._docker.side_effect = subprocess.CalledProcessError(1, ["docker"])
            with self.assertRaises(subprocess.CalledProcessError):
                root._cleanup(grant)
            self.assertFalse((case / "cleanup.json").exists())


if __name__ == "__main__":
    unittest.main()
