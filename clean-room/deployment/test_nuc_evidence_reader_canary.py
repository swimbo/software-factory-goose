import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('evidence_canary', pathlib.Path(__file__).with_name('nuc_evidence_reader_canary.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvidenceCanaryTests(unittest.TestCase):
    def test_unpinned_binary_cannot_plan(self):
        with mock.patch.object(module.os, 'geteuid', return_value=0), mock.patch.object(module, 'BINARY_SHA256', 'UNPINNED'):
            with self.assertRaisesRegex(RuntimeError, 'unpinned'):
                module.plan()

    def test_preexisting_directory_is_not_reused(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(module.os, 'geteuid', return_value=0), mock.patch.object(module, 'ROOT', pathlib.Path(root)), mock.patch.object(module, 'BINARY_SHA256', 'a' * 64), mock.patch.object(module, 'ancestors'):
            with self.assertRaisesRegex(RuntimeError, 'already exists'):
                module.plan()

    def test_plan_change_prevents_apply_before_creation(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(module, 'ROOT', pathlib.Path(root) / 'new'), mock.patch.object(module, 'plan', return_value={'scope': 'different'}):
            with self.assertRaisesRegex(RuntimeError, 'plan changed'):
                module.apply({'scope': 'reviewed'})
            self.assertFalse(module.ROOT.exists())


if __name__ == '__main__': unittest.main()
