"""Regressions discovered during local candidate review."""

import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from factory_harness import Broker, Denied, Profile, run_script
from harness_evaluation import workspace_hash


class Boundaries(unittest.TestCase):
    def test_snapshot_refuses_symlinked_ancestor(self):
        with (
            tempfile.TemporaryDirectory() as td,
            tempfile.TemporaryDirectory() as external,
        ):
            root = Path(td)
            subprocess.run(["git", "init", "-q", td], check=True)
            (root / "nested").mkdir()
            (root / "nested/data").write_text("original")
            subprocess.run(["git", "-C", td, "add", "nested/data"], check=True)
            (root / "nested/data").unlink()
            (root / "nested").rmdir()
            (Path(external) / "data").write_text("outside")
            (root / "nested").symlink_to(external, target_is_directory=True)
            with self.assertRaises((Denied, OSError)):
                workspace_hash(root)

    def test_late_normalization_never_releases_success(self):
        def delayed(text):
            time.sleep(0.15)
            return text

        b = Broker(Profile("v1", "g", "m", "r", "static", []), lambda *_: True, delayed)
        result = run_script(
            Path(os.environ["SFACTORY_TEST_SCRIPT_HOST"]), "return 1;", b, timeout=0.1
        )
        self.assertEqual(result["status"], "refused")

    def test_cancelled_host_is_reaped(self):
        original = subprocess.Popen
        children = []

        def tracked(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        b = Broker(
            Profile("v1", "g", "m", "r", "static", []), lambda *_: True, lambda s: s
        )
        with patch("factory_harness.subprocess.Popen", side_effect=tracked):
            result = run_script(
                Path(os.environ["SFACTORY_TEST_SCRIPT_HOST"]),
                "while(true){}",
                b,
                timeout=0.05,
            )
        self.assertEqual(result["status"], "refused")
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)


if __name__ == "__main__":
    unittest.main()
