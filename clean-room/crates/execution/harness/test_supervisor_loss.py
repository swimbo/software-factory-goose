"""Real Linux process-liveness boundaries used by the Root loss watchdog."""

import os
from pathlib import Path
import sys
import unittest


@unittest.skipUnless(sys.platform == "linux", "requires actual Linux /proc state")
class OwnerLivenessTests(unittest.TestCase):
    def test_current_process_requires_same_start_identity(self):
        from linux_supervisor import _owner_alive, _ticks

        pid = os.getpid()
        started = _ticks(pid)
        self.assertTrue(_owner_alive(pid, started))
        self.assertFalse(_owner_alive(pid, started + 1))

    def test_absent_process_is_not_an_owner(self):
        from linux_supervisor import _owner_alive

        self.assertFalse(_owner_alive(2**31 - 1, 1))

    def test_unreaped_zombie_is_lost_even_while_start_identity_matches(self):
        from linux_supervisor import _owner_alive, _ticks

        pid = os.fork()
        if pid == 0:
            os._exit(0)
        try:
            os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
            self.assertEqual(fields[0], "Z")
            self.assertEqual(_ticks(pid), int(fields[19]))
            self.assertFalse(_owner_alive(pid, int(fields[19])))
        finally:
            os.waitpid(pid, 0)


class WatchdogRetryTests(unittest.TestCase):
    def run_watchdog(self, failures, clock):
        import tempfile
        from unittest.mock import Mock, patch
        from linux_supervisor import watchdog

        with tempfile.TemporaryDirectory() as directory:
            backend = Mock()
            backend._case.return_value = Path(directory)
            backend.revoke.side_effect = failures
            with (
                patch("linux_supervisor.RootSupervisor", return_value=backend),
                patch("linux_supervisor.protected", return_value=b'{"fixture":true}'),
                patch("linux_supervisor._owner_alive", return_value=False),
                patch("linux_supervisor.time.monotonic", side_effect=clock),
                patch("linux_supervisor.time.sleep"),
            ):
                watchdog("fixture-config", "fixture-id", 123, 456)
            self.assertFalse((Path(directory) / "cleanup.json").exists())
            return backend

    def test_transient_cleanup_error_retries_only_revocation(self):
        backend = self.run_watchdog([OSError("daemon unavailable"), None], [0, 0])
        self.assertEqual(backend.revoke.call_count, 2)
        backend.prepare.assert_not_called()
        backend.start.assert_not_called()

    def test_retry_budget_exhaustion_never_reports_cleanup_or_relaunch(self):
        backend = self.run_watchdog([OSError("daemon unavailable")], [0, 30])
        self.assertEqual(backend.revoke.call_count, 1)
        backend.prepare.assert_not_called()
        backend.start.assert_not_called()


class ScopeRevocationTests(unittest.TestCase):
    """Real revoke entry point and on-disk state; wallet/kernel are explicit seams."""

    def exercise(self, *, cleanup_error=None, owner_error=None, changed=False):
        import tempfile
        from unittest.mock import Mock, patch
        import linux_supervisor as product

        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {"attempt_id": "run_" + "a" * 64}
            product.store(case / "grant.json", grant)
            product.store(
                case / "owner-scope.json",
                {
                    "grant_sha256": "f" * 64 if changed else product.sha(grant),
                    "scope_sha256": "b" * 64,
                },
            )
            backend = object.__new__(product.RootSupervisor)
            backend._case = lambda _: case
            events = []

            def cleanup(_):
                events.append("execution_fenced")
                if cleanup_error:
                    raise cleanup_error

            def revoke(scope):
                events.append(("owner_revoke", scope))
                if owner_error:
                    raise owner_error

            backend._cleanup = cleanup
            backend.owner = Mock()
            backend.owner.revoke.side_effect = revoke
            with patch.object(
                product,
                "protected",
                side_effect=lambda p, *a, **k: Path(p).read_bytes(),
            ):
                try:
                    result = backend.revoke({"grant": grant})
                    error = None
                except Exception as exc:
                    result, error = None, exc
            return events, result, error, (case / "owner-revoked.json").exists()

    def test_observe_cannot_finish_revoked_execution_before_wallet_ack(self):
        import tempfile
        import threading
        from unittest.mock import Mock, patch
        import linux_supervisor as product

        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {"attempt_id": "run_" + "a" * 64, "expires_at_ms": 10**15}
            worker = {"public_fixture": True}
            for name, value in {
                "grant.json": grant,
                "worker.json": worker,
                "stop.json": {"grant_sha256": product.sha(grant)},
                "cleanup.json": {"grant_sha256": product.sha(grant), "state": "absent"},
                "owner-scope.json": {
                    "grant_sha256": product.sha(grant),
                    "scope_sha256": "b" * 64,
                },
            }.items():
                product.store(case / name, value)
            backend = object.__new__(product.RootSupervisor)
            backend._case = lambda _: case
            backend.guard = threading.Lock()
            backend._kernel_scope = Mock()
            backend.owner = Mock()
            backend.owner.revoke.side_effect = OSError("wallet unknown")
            with patch.object(
                product,
                "protected",
                side_effect=lambda p, *a, **k: Path(p).read_bytes(),
            ):
                with self.assertRaisesRegex(OSError, "wallet unknown"):
                    backend.observe({"grant": grant, "worker": worker})
                self.assertFalse((case / "finished.json").exists())
                backend.owner.revoke.side_effect = None
                backend.owner.revoke.return_value = None
                self.assertEqual(
                    backend.observe({"grant": grant, "worker": worker})["state"],
                    "finished",
                )
                self.assertTrue((case / "owner-revoked.json").exists())
                self.assertTrue((case / "finished.json").exists())

    def test_normal_terminal_observe_also_requires_scope_retirement(self):
        import tempfile
        import threading
        from unittest.mock import Mock, patch
        import linux_supervisor as product

        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {"attempt_id": "run_" + "a" * 64, "expires_at_ms": 10**15}
            worker = {"public_fixture": True}
            for name, value in {
                "grant.json": grant,
                "worker.json": worker,
                "owner-scope.json": {
                    "grant_sha256": product.sha(grant),
                    "scope_sha256": "b" * 64,
                },
            }.items():
                product.store(case / name, value)
            backend = object.__new__(product.RootSupervisor)
            backend._case = lambda _: case
            backend.guard = threading.Lock()
            backend._inspect = Mock(
                return_value={"State": {"Running": False, "ExitCode": 0}}
            )
            backend._current = Mock()
            backend._cleanup = Mock()
            backend.owner = Mock()
            backend.owner.revoke.side_effect = OSError("wallet unknown")
            with patch.object(
                product,
                "protected",
                side_effect=lambda p, *a, **k: Path(p).read_bytes(),
            ):
                with self.assertRaisesRegex(OSError, "wallet unknown"):
                    backend.observe({"grant": grant, "worker": worker})
                backend._cleanup.assert_called_once_with(grant)
                self.assertFalse((case / "finished.json").exists())
                backend.owner.revoke.side_effect = None
                backend.owner.revoke.return_value = None
                self.assertEqual(
                    backend.observe({"grant": grant, "worker": worker})["exit_code"], 0
                )
                # Even a cached terminal record cannot bypass a corrupted owner acknowledgement.
                (case / "owner-revoked.json").write_text("{}")
                with self.assertRaises(product.SupervisorRefused):
                    backend.observe({"grant": grant, "worker": worker})

    def test_prepare_persists_admitted_scope_before_publishing_grant(self):
        import contextlib
        import tempfile
        import threading
        from unittest.mock import Mock, patch
        import linux_supervisor as product
        from test_linux_supervisor import SupervisorContractTests

        inputs = SupervisorContractTests()
        inputs.setUp()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            backend = object.__new__(product.RootSupervisor)
            backend.state, backend.runtime = base / "state", base / "runtime"
            backend.state.mkdir()
            backend.runtime.mkdir()
            backend.recipe = inputs.recipe
            backend.guard = threading.Lock()
            backend.gate = type(
                "FixtureGate", (), {"admission": staticmethod(contextlib.nullcontext)}
            )()
            backend._catalog = lambda *args: (inputs.entry, inputs.lease)
            backend._kernel_scope = Mock()
            events = []
            backend.owner = Mock()

            def admit(_):
                events.append("admitted")
                return inputs.entry["scope_sha256"]

            backend.owner.admit.side_effect = admit
            store = product.store

            def observe_store(path, value, mode=0o600):
                if path.name == "owner-scope.json":
                    self.assertEqual(events, ["admitted"])
                    events.append("scope_saved")
                if path.name == "grant.json":
                    self.assertEqual(events, ["admitted", "scope_saved"])
                    import json

                    scope = json.loads((path.parent / "owner-scope.json").read_bytes())
                    self.assertEqual(
                        scope,
                        {
                            "grant_sha256": product.sha(value),
                            "scope_sha256": inputs.entry["scope_sha256"],
                        },
                    )
                return store(path, value, mode)

            with (
                patch.object(product, "store", side_effect=observe_store),
                patch.object(product.os, "chown"),
                patch.object(product.time, "time_ns", return_value=1100000000),
            ):
                grant = backend.prepare(
                    {
                        "attempt": inputs.attempt,
                        "admission": inputs.admission,
                        "recipe": inputs.recipe,
                    }
                )
            self.assertTrue(
                (backend.state / grant["attempt_id"] / "grant.json").exists()
            )
            self.assertEqual(events, ["admitted", "scope_saved"])

    def test_confirmed_receipt_replays_without_another_wallet_call(self):
        import tempfile
        from unittest.mock import Mock, patch
        import linux_supervisor as product

        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            grant = {"attempt_id": "run_" + "a" * 64}
            scope = {"grant_sha256": product.sha(grant), "scope_sha256": "b" * 64}
            product.store(case / "grant.json", grant)
            product.store(case / "owner-scope.json", scope)
            backend = object.__new__(product.RootSupervisor)
            backend._case = lambda _: case
            backend._cleanup = Mock()
            backend.owner = Mock()
            backend.owner.revoke.return_value = None
            with patch.object(
                product,
                "protected",
                side_effect=lambda p, *a, **k: Path(p).read_bytes(),
            ):
                for _ in range(2):
                    self.assertEqual(
                        backend.revoke({"grant": grant})["state"], "stopped"
                    )
                backend.owner.revoke.assert_called_once_with("b" * 64)
                self.assertEqual(backend._cleanup.call_count, 2)
                # A changed completion receipt cannot manufacture a known revocation.
                (case / "owner-revoked.json").write_text("{}")
                with self.assertRaises(product.SupervisorRefused):
                    backend.revoke({"grant": grant})
                backend.owner.revoke.assert_called_once()

    def test_close_uses_saved_scope_even_after_catalog_retirement(self):
        import tempfile
        from unittest.mock import Mock, patch
        import linux_supervisor as product

        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            attempt = {"attempt_id": "run_" + "a" * 64}
            grant = {"attempt_id": attempt["attempt_id"]}
            product.store(case / "grant.json", grant)
            product.store(case / "prepare-intent.json", {"attempt": attempt})
            product.store(
                case / "owner-scope.json",
                {
                    "grant_sha256": product.sha(grant),
                    "scope_sha256": "b" * 64,
                },
            )
            backend = object.__new__(product.RootSupervisor)
            backend._case = lambda _: case
            backend._cleanup = Mock()
            backend.owner = Mock()
            backend.owner.revoke.return_value = None
            with patch.object(
                product,
                "protected",
                side_effect=lambda p, *a, **k: Path(p).read_bytes(),
            ):
                with self.assertRaises(product.SupervisorRefused):
                    backend.close({"attempt": attempt, "scope_sha256": "c" * 64})
                backend.owner.revoke.assert_not_called()
                self.assertFalse((case / "stop.json").exists())
                self.assertEqual(
                    backend.close({"attempt": attempt, "scope_sha256": "b" * 64}),
                    {
                        "scope_sha256": "b" * 64,
                        "status": "closed",
                    },
                )
                backend.owner.revoke.assert_called_once_with("b" * 64)

    def test_revocation_ack_is_required_before_stopped(self):
        events, result, error, receipt = self.exercise()
        self.assertEqual(events, ["execution_fenced", ("owner_revoke", "b" * 64)])
        self.assertIsNone(error)
        self.assertEqual(result["state"], "stopped")
        self.assertTrue(receipt)

    def test_daemon_failure_still_revokes_scope_without_reporting_stopped(self):
        events, result, error, receipt = self.exercise(
            cleanup_error=OSError("daemon unavailable")
        )
        self.assertEqual(events, ["execution_fenced", ("owner_revoke", "b" * 64)])
        self.assertIsNone(result)
        self.assertIsInstance(error, OSError)
        self.assertTrue(receipt)

    def test_wallet_unknown_does_not_prevent_execution_fence_or_claim_ack(self):
        events, result, error, receipt = self.exercise(
            owner_error=OSError("wallet unknown")
        )
        self.assertEqual(events, ["execution_fenced", ("owner_revoke", "b" * 64)])
        self.assertIsNone(result)
        self.assertIsInstance(error, OSError)
        self.assertFalse(receipt)

    def test_changed_saved_scope_is_not_sent_to_owner(self):
        events, result, error, receipt = self.exercise(changed=True)
        self.assertEqual(events, ["execution_fenced"])
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertFalse(receipt)


if __name__ == "__main__":
    unittest.main()
