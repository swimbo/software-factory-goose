"""Guard state contracts; actual PID1 execution is a separate native proof."""

import copy
import unittest

from linux_service_guard import GuardRefused, service_policy, validate_ready, unit_name


class GuardContractTests(unittest.TestCase):
    def setUp(self):
        self.grant = {"attempt_id": "run_" + "a" * 64, "boot_id": "boot"}
        self.intent = {
            "schema": 1,
            "grant_sha256": "a" * 64,
            "config_sha256": "b" * 64,
            "guard_sha256": "c" * 64,
            "supervisor_sha256": "d" * 64,
            "unit": "sfactoryguard" + "e" * 64 + ".service",
            "owner_pid": 100,
            "owner_ticks": 200,
            "owner_cgroup": "/system.slice/owner.service",
            "worker_cgroup": "/sfactoryharness.slice",
            "boot_id": "boot",
        }
        self.ready = dict(
            self.intent,
            pid=300,
            ticks=400,
            invocation_id="f" * 32,
            cgroup="/system.slice/guard.service",
        )
        self.snapshot = {
            "Id": self.intent["unit"],
            "ActiveState": "active",
            "SubState": "running",
            "MainPID": 300,
            "InvocationID": "f" * 32,
            "ControlGroup": self.ready["cgroup"],
        }

    def test_ready_binds_service_identity_and_all_saved_intent(self):
        self.assertEqual(
            validate_ready(self.intent, self.ready, self.snapshot), self.ready
        )
        for field, changed in (
            ("MainPID", 301),
            ("InvocationID", "0" * 32),
            ("ControlGroup", "/system.slice/reused.service"),
            ("ActiveState", "inactive"),
        ):
            with self.subTest(field=field), self.assertRaises(GuardRefused):
                validate_ready(
                    self.intent, self.ready, self.snapshot | {field: changed}
                )
        for field in self.intent:
            changed = dict(self.ready, **{field: "changed"})
            with self.subTest(field=field), self.assertRaises(GuardRefused):
                validate_ready(self.intent, changed, self.snapshot)
        with self.assertRaises(GuardRefused):
            validate_ready(self.intent, self.ready | {"extra": True}, self.snapshot)

    def test_guard_must_be_outside_owner_and_worker_subtrees(self):
        for group in (
            "/",
            self.intent["owner_cgroup"],
            self.intent["owner_cgroup"] + "/child",
            self.intent["worker_cgroup"],
            self.intent["worker_cgroup"] + "/child",
        ):
            ready = dict(self.ready, cgroup=group)
            with self.subTest(group=group), self.assertRaises(GuardRefused):
                validate_ready(
                    self.intent, ready, self.snapshot | {"ControlGroup": group}
                )

    def test_service_policy_has_no_restart_or_owner_lifetime_dependency(self):
        policy = service_policy(
            ["/usr/bin/python3", "-I", "/guard.py"],
            ["/usr/bin/python3", "-I", "/guard.py", "cleanup"],
            200000000,
        )
        values = {name: value for name, signature, value in policy}
        self.assertEqual(values["Restart"], "no")
        self.assertEqual(values["KillMode"], "control-group")
        self.assertEqual(values["RuntimeMaxUSec"], 200000000)
        self.assertEqual(values["TasksMax"], 32)
        self.assertEqual(values["MemoryMax"], 268435456)
        self.assertIn("ExecStopPost", values)
        self.assertFalse(set(values) & {"BindsTo", "PartOf", "Requires"})
        for bound in (True, 0, -1, 215000001):
            with self.subTest(bound=bound), self.assertRaises(GuardRefused):
                service_policy(["/python"], ["/python", "cleanup"], bound)

    def test_service_unit_is_deterministic_and_not_caller_supplied(self):
        name = unit_name(self.grant)
        self.assertEqual(name, unit_name(copy.deepcopy(self.grant)))
        self.assertRegex(name, r"^sfactoryguard[0-9a-f]{64}\.service$")
        self.assertNotEqual(name, unit_name(self.grant | {"changed": True}))


class GuardStartStateTests(unittest.TestCase):
    def test_binding_accepts_gateway_schemas_and_still_checks_pinned_inputs(self):
        import json
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import call, patch
        import linux_service_guard as guard

        cfg = {
            "schema": 4,
            "guard_program": str(Path(guard.__file__).resolve()),
            "supervisor_program": str(
                Path(guard.__file__).with_name("linux_supervisor.py").resolve()
            ),
            "python": "/fixture/python",
            "systemd_library": "/fixture/systemd",
            **{
                name + "_sha256": str(index) * 64
                for index, name in enumerate(
                    (
                        "guard_program",
                        "supervisor_program",
                        "python",
                        "systemd_library",
                    ),
                    1,
                )
            },
        }
        backend = SimpleNamespace(cfg=cfg, configuration=Path("/fixture/config"))
        with (
            patch.object(guard, "_immutable") as immutable,
            patch("linux_supervisor.protected", return_value=json.dumps(cfg).encode()),
        ):
            result = guard._binding(backend)
            self.assertEqual(result["config_sha256"], guard.sha(cfg))
            self.assertEqual(result["guard_sha256"], cfg["guard_program_sha256"])
            self.assertEqual(
                result["supervisor_sha256"], cfg["supervisor_program_sha256"]
            )
            self.assertEqual(
                immutable.call_args_list,
                [
                    call(cfg[name], cfg[name + "_sha256"])
                    for name in (
                        "guard_program",
                        "supervisor_program",
                        "python",
                        "systemd_library",
                    )
                ],
            )
            for invalid in (1, 6, 4.0, True):
                with self.subTest(schema=invalid), self.assertRaises(GuardRefused):
                    guard._binding(SimpleNamespace(cfg=cfg | {"schema": invalid}))

        for schema in (2, 3, 5):
            prior = cfg | {"schema": schema}
            with (
                self.subTest(schema=schema),
                patch.object(guard, "_immutable"),
                patch(
                    "linux_supervisor.protected",
                    return_value=json.dumps(prior).encode(),
                ),
            ):
                self.assertEqual(
                    guard._binding(SimpleNamespace(cfg=prior, configuration="/config"))[
                        "config_sha256"
                    ],
                    guard.sha(prior),
                )

        with (
            patch.object(guard, "_immutable"),
            patch("linux_supervisor.protected", return_value=b"{}"),
            self.assertRaisesRegex(GuardRefused, "guard_configuration_changed"),
        ):
            guard._binding(backend)

    def test_unknown_pid1_ack_never_dispatches_a_second_service(self):
        import json
        import tempfile
        import time
        from pathlib import Path
        from unittest.mock import Mock, patch
        import linux_service_guard as guard

        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {
                "attempt_id": "run_" + "a" * 64,
                "boot_id": "boot",
                "cgroup_path": "/sys/fs/cgroup/worker.slice",
                "expires_at_ms": time.time_ns() // 1000000 + 180000,
            }
            backend = Mock()
            backend._saved.return_value = case
            backend.cfg = {"python": "/python", "guard_program": "/guard.py"}
            backend.configuration = "/config.json"
            binding = {
                "config_sha256": "b" * 64,
                "guard_sha256": "c" * 64,
                "supervisor_sha256": "d" * 64,
            }
            manager = Mock()
            manager.__enter__ = Mock(return_value=manager)
            manager.__exit__ = Mock(return_value=False)
            manager.start.side_effect = OSError("PID1 acknowledgement unknown")
            # This is durable one-use state proof, not a Root/PID1 identity proof.
            with (
                patch.object(guard, "_binding", return_value=binding),
                patch.object(guard, "_manager", return_value=manager),
                patch.object(guard, "_process_group", return_value="/owner.service"),
                patch("linux_supervisor._ticks", return_value=123),
            ):
                with self.assertRaisesRegex(OSError, "acknowledgement unknown"):
                    guard.start_guard(backend, grant)
                saved = (case / "guard-intent.json").read_bytes()
                self.assertEqual(json.loads(saved)["unit"], guard.unit_name(grant))
                self.assertFalse((case / "guard-ready.json").exists())
                with self.assertRaisesRegex(guard.GuardRefused, "already_attempted"):
                    guard.start_guard(backend, grant)
                self.assertEqual((case / "guard-intent.json").read_bytes(), saved)
                manager.start.assert_called_once()

    def test_root_start_refuses_before_any_docker_request_without_guard_ready(self):
        from pathlib import Path
        import tempfile
        from unittest.mock import Mock, patch
        import linux_supervisor as product
        from test_supervisor_start_loss import StartLossStateTests

        with tempfile.TemporaryDirectory() as directory:
            backend, case, _, body = StartLossStateTests().make(directory)
            backend._catalog = lambda *args: (
                {
                    "factory_task_id": "public-fixture",
                    "scope": {"generation": "public-generation"},
                },
                {},
            )
            backend._docker = Mock()
            with (
                patch.object(
                    product,
                    "protected",
                    side_effect=lambda p, *args, **kwargs: Path(p).read_bytes(),
                ),
                patch.object(
                    product,
                    "start_guard",
                    side_effect=GuardRefused("guard_readiness_unknown"),
                ),
            ):
                with self.assertRaisesRegex(GuardRefused, "guard_readiness_unknown"):
                    backend.start(body)
            backend._docker.assert_not_called()
            self.assertTrue((case / "start-intent.json").exists())
            self.assertFalse((case / "container.json").exists())
            self.assertFalse((case / "worker.json").exists())


class GuardMutationGateTests(unittest.TestCase):
    """Actual start-state transitions; filesystem and Docker are explicit seams."""

    def exercise(self, failure_at):
        import os
        import stat
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        import linux_supervisor as product
        from test_supervisor_start_loss import StartLossStateTests

        with tempfile.TemporaryDirectory() as directory:
            backend, case, _, body = StartLossStateTests().make(directory)
            public = case / "public-input"
            public.write_bytes(b"public source placeholder")
            body["grant"].update(
                relay_path=str(public), cgroup_path="/sys/fs/cgroup/public.slice"
            )
            backend.cfg = {
                "goose": str(public),
                "worker_program": str(public),
                "worker_program_sha256": "b" * 64,
            }
            backend._catalog = lambda *args: (
                {"factory_task_id": "public", "scope": {"generation": "public"}},
                {},
            )
            backend._inspect = Mock()
            backend._worker = Mock()
            calls = []

            def docker(*args):
                calls.append(args)
                if args[0] == "info":
                    return b"systemd"
                if args[:2] == ("image", "inspect"):
                    return b'[{"Config":{}}]'
                if args[0] == "create":
                    return b"c" * 64
                raise AssertionError("unexpected Docker mutation: " + args[0])

            backend._docker = docker
            opened = {}
            actual_open, actual_stat = os.open, os.fstat
            opath = getattr(os, "O_PATH", 1 << 28)

            def source_open(path, flags, *args, **kwargs):
                if flags == opath | os.O_NOFOLLOW:
                    descriptor = actual_open(public, os.O_RDONLY)
                    relay = str(path) == str(public)
                    # Goose/worker use the same placeholder too; the actual
                    # loop visits them before its final relay entry.
                    relay = relay and len(opened) == 5
                    opened[descriptor] = SimpleNamespace(
                        st_mode=(stat.S_IFSOCK | 0o660)
                        if relay
                        else (stat.S_IFREG | 0o444),
                        st_uid=2005 if relay else 0,
                        st_gid=2001 if relay else 0,
                    )
                    return descriptor
                return actual_open(path, flags, *args, **kwargs)

            checks = [None] * (failure_at - 1) + [GuardRefused("guard identity lost")]
            with (
                patch.object(
                    product,
                    "protected",
                    side_effect=lambda p, *a, **k: Path(p).read_bytes(),
                ),
                patch.object(product, "start_guard"),
                patch.object(product, "check_guard", side_effect=checks),
                patch.object(product.os, "O_PATH", opath, create=True),
                patch.object(product.os, "open", side_effect=source_open),
                patch.object(
                    product.os,
                    "fstat",
                    side_effect=lambda fd: opened.get(fd) or actual_stat(fd),
                ),
                patch.object(
                    product,
                    "stage_launch_source",
                    side_effect=lambda fd,
                    source,
                    target,
                    expected: "/var/lib/sfactory-harness/public/"
                    + body["grant"]["attempt_id"]
                    + "/mounts/"
                    + target.name,
                ),
            ):
                with self.assertRaisesRegex(GuardRefused, "guard identity lost"):
                    backend.start(body)
            self.assertTrue((case / "start-intent.json").exists())
            self.assertEqual((case / "container.json").exists(), failure_at == 2)
            self.assertFalse((case / "worker.json").exists())
            backend._worker.assert_not_called()
            return [call[0] for call in calls]

    def test_guard_loss_before_create_prevents_both_mutations(self):
        self.assertEqual(self.exercise(1), ["info", "image"])

    def test_guard_loss_after_create_retains_container_but_prevents_start(self):
        self.assertEqual(self.exercise(2), ["info", "image", "create"])


class SystemdSnapshotContractTests(unittest.TestCase):
    def test_control_group_is_a_service_property_not_a_unit_property(self):
        from linux_service_guard import SystemdManager

        unit = "sfactoryguard" + "a" * 64 + ".service"
        manager = object.__new__(SystemdManager)
        manager._call = lambda *args: "/org/freedesktop/systemd1/unit/public"
        # Public PID1 D-Bus contract, independently confirmed by native probes.
        unit_properties = {
            ("Id", "s"): unit,
            ("ActiveState", "s"): "active",
            ("SubState", "s"): "running",
            ("InvocationID", "ay"): "b" * 32,
        }
        service_properties = {
            ("ControlGroup", "s"): "/system.slice/" + unit,
            ("MainPID", "u"): 123,
        }

        def property_value(path, interface, name, signature):
            self.assertEqual(path, "/org/freedesktop/systemd1/unit/public")
            values = {
                "org.freedesktop.systemd1.Unit": unit_properties,
                "org.freedesktop.systemd1.Service": service_properties,
            }
            try:
                return values[interface][name, signature]
            except KeyError:
                raise GuardRefused("PID1 property interface mismatch") from None

        manager._property = property_value
        self.assertEqual(
            manager.snapshot(unit),
            {
                "Id": unit,
                "ActiveState": "active",
                "SubState": "running",
                "InvocationID": "b" * 32,
                "MainPID": 123,
                "ControlGroup": "/system.slice/" + unit,
            },
        )


class FixtureRetirementTests(unittest.TestCase):
    def test_only_exact_stopped_acknowledgement_retires_the_owned_slice(self):
        import importlib.util
        from pathlib import Path
        import sys
        from unittest.mock import Mock, patch
        import linux_supervisor as product

        path = (
            Path(__file__).resolve().parents[3]
            / "tests/fixtures/harness_pid1_guard_replay.py"
        )
        spec = importlib.util.spec_from_file_location(
            "guard_qualification_fixture", path
        )
        fixture = importlib.util.module_from_spec(spec)
        original_path = list(sys.path)
        try:
            spec.loader.exec_module(fixture)
        finally:
            sys.path[:] = original_path
        grant = {"attempt_id": "run_" + "a" * 64}
        group = Path("/sys/fs/cgroup/sfactoryharness" + "a" * 64 + ".slice")
        for answer in (
            OSError("acknowledgement unknown"),
            {"state": "stopped"},
            {"grant_sha256": "b" * 64, "state": "stopped"},
            {"grant_sha256": product.sha(grant), "state": "stopped"},
        ):
            backend = Mock()
            if isinstance(answer, Exception):
                backend.revoke.side_effect = answer
            else:
                backend.revoke.return_value = answer
            expected = answer == {
                "grant_sha256": product.sha(grant),
                "state": "stopped",
            }
            with (
                self.subTest(answer=str(answer)),
                patch.object(fixture.product, "RootSupervisor", return_value=backend),
                patch.object(fixture.prior, "slice_unit") as stop,
            ):
                self.assertEqual(
                    fixture.retire_worker_slice("public-config", grant, group), expected
                )
                if expected:
                    stop.assert_called_once_with("StopUnit", group.name)
                else:
                    stop.assert_not_called()
