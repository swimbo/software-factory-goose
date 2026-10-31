import unittest
from linux_runner import recipe, validate_grant, validate_worker, LinuxRunnerRefused
from linux_goose_runtime import LINUX_GOOSE_SHA256


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.attempt = dict(
            attempt_id="run_" + "a" * 64,
            task_id="task-1",
            suite_sha256="b" * 64,
            config_sha256="c" * 64,
            goose_build=LINUX_GOOSE_SHA256,
            variant="candidate",
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
            profiles={"baseline": "f" * 64, "candidate": "d" * 64},
            script_host_sha256="1" * 64,
            normalizer_sha256="2" * 64,
            broker_uid=2000,
            worker_uid=2001,
            max_runtime_ms=180000,
        )
        self.admission = dict(
            attempt_id=self.attempt["attempt_id"],
            status="allowed",
            authority_receipt_sha256="3" * 64,
        )
        from protected_goose_runtime import sha

        self.grant = dict(
            schema=1,
            attempt_id=self.attempt["attempt_id"],
            attempt_sha256=sha(self.attempt),
            admission_sha256=sha(self.admission),
            recipe_sha256=sha(self.recipe),
            grant_id="4" * 64,
            issued_at_ms=1000,
            expires_at_ms=181000,
            worker_uid=2001,
            broker_uid=2000,
            boot_id="11111111-1111-4111-8111-111111111111",
            cgroup_dev=1,
            cgroup_ino=2,
            cgroup_path="/sys/fs/cgroup/sfactoryharness" + "a" * 64 + ".slice",
            workspace_path="/owned/run_" + "a" * 64 + "/work",
            relay_path="/owned/run_" + "a" * 64 + "/relay.sock",
        )

    def check(self, grant):
        return validate_grant(
            grant, self.attempt, self.admission, self.recipe, "/owned", now_ms=1001
        )

    def test_exact_generic_recipe_accepts_both_variants_and_arbitrary_suite_task(self):
        self.assertEqual(self.check(self.grant), self.grant)
        self.assertEqual(self.recipe["purpose"], "sfactory-harness-linux-v1")
        self.assertIs(self.recipe["candidate_enabled"], False)

    def test_changed_authority_scope_budget_profile_and_paths_refuse(self):
        for field, value in [
            ("recipe_sha256", "0" * 64),
            ("attempt_sha256", "0" * 64),
            ("admission_sha256", "0" * 64),
            ("workspace_path", "/etc/work"),
            ("relay_path", "/other.sock"),
            ("worker_uid", 2000),
            ("expires_at_ms", 181001),
        ]:
            with self.subTest(field=field), self.assertRaises(LinuxRunnerRefused):
                self.check(self.grant | {field: value})
        for field, value in [
            ("budget", 750001),
            ("daily_cap", 5000001),
            ("profile", "0" * 64),
        ]:
            before = self.attempt
            self.attempt = before | {field: value}
            with self.assertRaises(LinuxRunnerRefused):
                self.check(self.grant)
            self.attempt = before

    def test_kernel_observations_bind_role_namespace_and_grant(self):
        from protected_goose_runtime import sha

        observed = dict(
            schema=1,
            grant_sha256=sha(self.grant),
            pid=99,
            start_ticks=100,
            worker_uid=2001,
            no_new_privs=1,
            seccomp=2,
            network_dev=2,
            network_ino=3,
            boot_id=self.grant["boot_id"],
            cgroup_dev=1,
            cgroup_ino=2,
        )
        self.assertEqual(
            validate_worker(observed, self.grant, host_network=(2, 4)), observed
        )
        for changes in (
            {"worker_uid": 2000},
            {"no_new_privs": 0},
            {"seccomp": 0},
            {"network_ino": 4},
            {"grant_sha256": "0" * 64},
        ):
            with self.assertRaises(LinuxRunnerRefused):
                validate_worker(observed | changes, self.grant, host_network=(2, 4))

    def test_unknown_fields_expiry_and_impossible_roles_refuse(self):
        with self.assertRaises(LinuxRunnerRefused):
            self.check(self.grant | {"approved": True})
        with self.assertRaises(LinuxRunnerRefused):
            validate_grant(
                self.grant,
                self.attempt,
                self.admission,
                self.recipe,
                "/owned",
                now_ms=181000,
            )
        with self.assertRaises(LinuxRunnerRefused):
            recipe(
                suite_sha256="b" * 64,
                config_sha256="c" * 64,
                profiles={"baseline": "f" * 64, "candidate": "d" * 64},
                script_host_sha256="1" * 64,
                normalizer_sha256="2" * 64,
                broker_uid=2000,
                worker_uid=2000,
                max_runtime_ms=180000,
            )


class AdmissionOrderingTests(unittest.TestCase):
    def make(self):
        from linux_runner import LinuxRunnerAdapter
        from pathlib import Path
        from unittest.mock import Mock

        f = ContractTests()
        f.setUp()
        adapter = object.__new__(LinuxRunnerAdapter)
        adapter.recipe = f.recipe
        adapter.root = Path("/owned")
        adapter.grants = {}
        adapter.control = Mock()
        adapter.control.admit.return_value = f.admission
        adapter.supervisor = Mock(side_effect=RuntimeError("must not run"))
        return adapter, f

    def test_invalid_attempt_cannot_reach_root_prepare_even_if_control_errs(self):
        adapter, f = self.make()
        with self.assertRaises(LinuxRunnerRefused):
            adapter.admit(f.attempt | {"profile": "0" * 64})
        adapter.supervisor.assert_not_called()

    def test_existing_live_denial_prevents_all_root_mutation(self):
        adapter, f = self.make()
        denied = f.admission | {"status": "denied"}
        adapter.control.admit.return_value = denied
        self.assertEqual(adapter.admit(f.attempt), denied)
        adapter.supervisor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
