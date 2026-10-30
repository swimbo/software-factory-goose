import copy
import unittest

import nuc_root_finalization_prepare as p


class Preparation(unittest.TestCase):
    def fixture(self):
        scope = {'task_id': p.TASK, 'generation': p.G}
        reservation = {'generation': p.G, 'scope': scope}
        recipe = {'generation': p.G, 'task_id': p.TASK}
        catalog = {'scope': scope, 'recipe_sha256': p.sha(p.canonical(recipe)),
                   'boot_id': 'fixed-boot', 'cgroup_dev': 29, 'cgroup_ino': 12}
        left, right = p.canonical(reservation), p.canonical(catalog)
        binding = p.sha(b'sfactory-root-grant-v1\0' + len(left).to_bytes(8, 'big')
                        + left + len(right).to_bytes(8, 'big') + right)
        return {'grant': {'schema': 1, 'generation': p.G, 'reservation': reservation,
                          'binding_sha256': binding}, 'catalog': catalog, 'recipe': recipe,
                'observation': {'target_id': p.G, 'boot_id': 'fixed-boot',
                                'cgroup_dev': 29, 'cgroup_ino': 12, 'observed': True,
                                'observed_at_unix': 7, 'engine_reconciled': False},
                'runtime': {'boot_id': 'fixed-boot', 'namespace_dev': 4, 'namespace_ino': 2,
                            'host_namespace_dev': 4, 'host_namespace_ino': 1},
                'digests': {key: 'a' * 64 for key in ('grant', 'catalog', 'recipe', 'observation')}}

    def test_unknown_never_invents_spend_or_cleanup_success(self):
        request, config = p.build(**self.fixture())
        body, cfg = p.strict(request), p.strict(config)
        self.assertEqual(body['spend'], 'unknown')
        self.assertEqual(body['evidence'], {'kind': 'unknown', 'phase': 'cleanup',
                                          'reason': 'outcome_unknown', 'observation_sha256': 'a' * 64})
        self.assertEqual(cfg['request_sha256'], p.sha(request))
        self.assertNotIn('cleanup', body['evidence'])

    def test_substitution_of_actual_root_binding_or_observation_denies(self):
        changes = [('grant', 'binding_sha256', 'f' * 64),
                   ('recipe', 'task_id', 'another-task'),
                   ('observation', 'cgroup_ino', 99),
                   ('observation', 'engine_reconciled', True),
                   ('runtime', 'boot_id', 'another-boot')]
        for section, field, value in changes:
            with self.subTest(section=section, field=field), self.assertRaises(RuntimeError):
                fixture = copy.deepcopy(self.fixture())
                fixture[section][field] = value
                p.build(**fixture)

    def test_duplicate_or_nonfinite_inputs_deny(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.subTest(raw=raw), self.assertRaises((RuntimeError, ValueError)):
                p.strict(raw)


if __name__ == '__main__':
    unittest.main()
