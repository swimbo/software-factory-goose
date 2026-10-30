import hashlib,pathlib,unittest
from unittest.mock import patch
import nuc_eval_canary_provision as m
class CanaryProvision(unittest.TestCase):
 def test_distinct_stable_fixture_targets_and_pinned_sources(self):
  targets=[m.target(i) for i in range(1,23)]
  self.assertEqual(len(set(targets)),22);self.assertNotIn(m.G,targets);self.assertTrue(all(len(t)==26 and t[0] in '01234567' for t in targets));self.assertEqual(len(m.PINS),12)
  for name,digest in m.PINS.items():self.assertEqual(hashlib.sha256((pathlib.Path(__file__).parent/name).read_bytes()).hexdigest(),digest)
 def test_unreviewed_plan_cannot_create(self):
  with patch.object(m,'plan',return_value={'x':1}),patch.object(m.old,'store') as store,patch.object(m.os,'mkdir') as mkdir:
   with self.assertRaises(RuntimeError):m.apply({'x':2})
   store.assert_not_called();mkdir.assert_not_called()
 def test_fixture_candidate_not_holdout(self):
  self.assertEqual(set(m.FILES),{'hello.py','test_hello.py'});self.assertNotIn(b'Zo\xc3\xab Smith',m.REFERENCE);self.assertEqual(hashlib.sha256(m.REFERENCE).hexdigest(),m.sha(m.REFERENCE))
if __name__=='__main__':unittest.main()
