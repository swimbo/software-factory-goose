import unittest
from unittest.mock import patch
import nuc_eval_canary_run as m
class RunTests(unittest.TestCase):
 def test_stale_review_denies_before_persistent_or_systemd_effect(self):
  with patch.object(m,'plan',return_value={'x':1}),patch.object(m.old,'store') as store,patch.object(m.subprocess,'run') as run:
   with self.assertRaises(RuntimeError):m.apply({'x':2})
   store.assert_not_called();run.assert_not_called()
 def test_fixed_coordinator_program_checks_kernel_identity(self):
  compile(m.CODE,'<fixed-coordinator>','exec')
  for field in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb','NoNewPrivs'):self.assertIn(field,m.CODE)
if __name__=='__main__':unittest.main()
