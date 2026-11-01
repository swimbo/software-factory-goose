import unittest
from unittest.mock import patch
import nuc_sdk5_fd_guard_recovery as x
class Recovery(unittest.TestCase):
 def test_positive_must_be_exact_live_invocation_and_journal(self):
  name=x.original.POS; fields={'Names':name,'LoadState':'loaded','ActiveState':'active','SubState':'exited','MainPID':'0','Job':'','Result':'success','ExecMainStatus':'0','InvocationID':'a'*32,'User':'sfgoose-control','Group':'sfgoose-control','NoNewPrivileges':'yes','CapabilityBoundingSet':'','FragmentPath':str(x.old.UNIT/name),'DropInPaths':''}
  with patch.object(x.old,'ctl',side_effect=lambda *a:fields[a[3]]),patch.object(x.original,'journal',return_value=b'sdk5-startup-guard-passed\n'):
   self.assertEqual(x.positive(),'a'*32)
   fields['InvocationID']='0'*32
   with self.assertRaises(RuntimeError):x.positive()
   fields['InvocationID']='a'*32;fields['Result']='exit-code'
   with self.assertRaises(RuntimeError):x.positive()
 def test_negative_uses_distinct_fixed_wrapper(self):
  self.assertNotEqual(x.NEG,x.original.NEG);self.assertNotEqual(x.WRAPPER,x.original.WRAPPER);self.assertIn(str(x.WRAPPER).encode(),x.unit())
