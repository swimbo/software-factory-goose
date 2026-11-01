import importlib.util
import pathlib
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('root_finalization_attest', pathlib.Path(__file__).with_name('nuc_root_finalization_attest.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AttestationTests(unittest.TestCase):
    def test_duplicate_keys_and_nonfinite_values_are_rejected(self):
        for raw in (b'{"generation":"a","generation":"b"}', b'{"value":NaN}'):
            with self.assertRaises((RuntimeError, ValueError)):
                module.strict_json(raw)

    def test_changed_manager_identity_refuses_before_writes(self):
        with mock.patch.object(module, 'plan', return_value={'main_pid': 42}), mock.patch.object(module.old, 'store') as store:
            with self.assertRaisesRegex(RuntimeError, 'state changed'):
                module.apply({'main_pid': 41})
            store.assert_not_called()

    def test_post_intent_identity_change_never_publishes_manifest(self):
        with mock.patch.object(module, 'plan', side_effect=[{'main_pid':42}, {'main_pid':43}]), mock.patch.object(module.old, 'store') as store:
            with self.assertRaisesRegex(RuntimeError, 'after intent'):
                module.apply({'main_pid':42})
            self.assertEqual(store.call_count, 1)
            self.assertEqual(store.call_args.args[0], module.INTENT)


if __name__ == '__main__': unittest.main()
