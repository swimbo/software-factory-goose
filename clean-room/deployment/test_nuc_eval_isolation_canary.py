import unittest
from unittest.mock import patch
import nuc_eval_isolation_canary as m
class Isolation(unittest.TestCase):
 def test_mismatched_plan_never_mutates(self):
  with patch.object(m,'plan',return_value={'x':1}),patch.object(m.old,'store') as store:
   with self.assertRaises(RuntimeError):m.apply({'x':2})
   store.assert_not_called()
 def test_worker_probe_never_reads_host_files(self):
  code=m.CODE.decode();compile(code,'<isolation>','exec');self.assertIn('os.open',code);self.assertNotIn('os.read(',code);self.assertIn('CapBnd',code);self.assertIn('NoNewPrivs',code);self.assertIn('Seccomp',code)
if __name__=='__main__':unittest.main()
