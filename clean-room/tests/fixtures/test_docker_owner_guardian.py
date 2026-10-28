#!/usr/bin/env python3
"""Owned Docker fixture tests, including a killed external controller."""
import json
import queue
import subprocess
import sys
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from docker_owner_guardian import DisposableContainer, LABEL, docker

class GuardTests(unittest.TestCase):
    def test_mismatch_never_mutates(self):
        owner = DisposableContainer()
        owner.ident = "a" * 64
        for ident, label in [("a" * 64, "wrong"), ("b" * 64, owner.token)]:
            obj = {"Id": ident, "Config": {"Labels": {LABEL: label}}, "State": {"Running": True}}
            result = subprocess.CompletedProcess([], 0, json.dumps([obj]), "")
            with patch("docker_owner_guardian.docker", return_value=result) as call:
                with self.assertRaises(RuntimeError):
                    owner.cleanup()
                self.assertEqual([x.args[0] for x in call.call_args_list], ["inspect"])
                self.assertTrue(owner.closed)
                with self.assertRaises(RuntimeError):
                    owner.start()

    def test_failed_kill_quarantines_and_never_removes(self):
        owner = DisposableContainer()
        owner.ident = "a" * 64
        obj = {"Id": owner.ident, "Config": {"Labels": {LABEL: owner.token}}, "State": {"Running": True}}
        inspected = subprocess.CompletedProcess([], 0, json.dumps([obj]), "")
        with patch("docker_owner_guardian.docker", side_effect=[inspected, subprocess.TimeoutExpired("kill", 8)]) as call:
            with self.assertRaises(subprocess.TimeoutExpired):
                owner.cleanup()
            self.assertEqual([x.args[0] for x in call.call_args_list], ["inspect", "kill"])
            self.assertFalse(owner.removed)
            self.assertTrue(owner.closed)
            with self.assertRaises(RuntimeError):
                owner.start()

    def test_controller_kill_triggers_owned_cleanup(self):
        token = uuid.uuid4().hex
        fallback = DisposableContainer(token)
        controller = subprocess.Popen(["/bin/sleep", "30"], stdout=subprocess.PIPE)
        guardian = subprocess.Popen([sys.executable, "clean-room/tests/fixtures/docker_owner_guardian.py", token],
            stdin=controller.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        controller.stdout.close()
        lines = queue.Queue()
        def read_lines():
            for line in guardian.stdout:
                lines.put(line.strip())
        threading.Thread(target=read_lines, daemon=True).start()
        try:
            first = lines.get(timeout=15)
            self.assertTrue(first.startswith("READY "), first)
            ident = first.split()[1]
            fallback.ident = ident
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                logs = docker("logs", ident, check=False)
                if "ESCAPED_AFTER_GUARDIAN" in logs.stdout + logs.stderr:
                    break
                time.sleep(0.1)
            else:
                self.fail("escaped child did not survive its inner guardian")
            self.assertIsNone(guardian.poll(), "host guardian stopped before controller")
            controller.kill()
            controller.wait(timeout=5)
            self.assertEqual(lines.get(timeout=15), "REMOVED EOF")
            self.assertEqual(guardian.wait(timeout=5), 0)
            self.assertIsNone(fallback.inspect(ident))
        finally:
            if controller.poll() is None:
                controller.kill()
            controller.wait(timeout=5)
            try:
                guardian.wait(timeout=15)
            except subprocess.TimeoutExpired:
                guardian.kill()
                guardian.wait(timeout=5)
            # Only this exact random name/label, or the returned verified ID, can be cleaned.
            if fallback.inspect(fallback.ident or fallback.name) is not None:
                fallback.cleanup()
            guardian.stdout.close()
            guardian.stderr.close()

if __name__ == "__main__":
    unittest.main()
