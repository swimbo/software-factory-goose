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


if __name__ == "__main__":
    unittest.main()
