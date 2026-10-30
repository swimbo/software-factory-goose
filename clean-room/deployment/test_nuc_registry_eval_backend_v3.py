import contextlib,io,unittest
from unittest.mock import patch
import nuc_registry_eval_backend_v3 as m
class DiagnosticTests(unittest.TestCase):
 def test_failure_emits_only_fixed_stage_not_exception(self):
  b=m.Backend.__new__(m.Backend);err=io.StringIO()
  with patch.object(b,'_launch',side_effect=RuntimeError('private detail')),contextlib.redirect_stderr(err):
   with self.assertRaises(RuntimeError):b.launch_and_reconcile({},'a'*64)
  self.assertEqual(err.getvalue(),'evaluator backend unavailable stage=admission\n')
if __name__=='__main__':unittest.main()
