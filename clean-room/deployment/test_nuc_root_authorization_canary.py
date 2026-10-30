import importlib.util
import pathlib
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('authorization_canary', pathlib.Path(__file__).with_name('nuc_root_authorization_canary.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AuthorizationCanaryTests(unittest.TestCase):
    def test_missing_binary_pin_refuses(self):
        with self.assertRaisesRegex(RuntimeError, 'unpinned'):
            module.pin(pathlib.Path('/not-opened'), 'UNPINNED')

    def test_changed_plan_cannot_create_intent(self):
        with mock.patch.object(module, 'plan', return_value={'generation':'other'}), mock.patch.object(module, 'create') as create:
            with self.assertRaisesRegex(RuntimeError, 'scope changed'):
                module.apply({'generation':'reviewed'})
            create.assert_not_called()

    def test_fixture_generations_are_distinct(self):
        self.assertEqual(len(module.GENS),len(set(module.GENS)))
        self.assertNotIn('01M65RMR3F04YB1B016EBBSXGG',module.GENS)


if __name__ == '__main__': unittest.main()
