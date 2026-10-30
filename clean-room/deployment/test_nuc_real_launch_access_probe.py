import unittest
from unittest import mock
import nuc_real_launch_access_probe as p
class Probe(unittest.TestCase):
 def test_changed_plan_never_starts_or_writes(self):
  with mock.patch.object(p,'plan',return_value={'x':1}),mock.patch.object(p.old,'store') as store,mock.patch.object(p,'run') as run:
   with self.assertRaises(RuntimeError):p.apply({'x':2})
   store.assert_not_called();run.assert_not_called()
if __name__=='__main__':unittest.main()

class Outcome(unittest.TestCase):
 def test_wrong_capability_result_cannot_record_success(self):
  approved={'paths':[]}
  results=[{'mode':'empty','paths':['opened','opened'],'cap_eff':0},{'mode':'dac-read-search','paths':['opened','opened'],'cap_eff':4}]
  with mock.patch.object(p,'plan',return_value=approved),mock.patch.object(p.old,'store') as store,mock.patch.object(p,'run',side_effect=results):
   with self.assertRaises(RuntimeError):p.apply(approved)
   self.assertEqual(store.call_count,1);self.assertEqual(store.call_args.args[0],p.START)
