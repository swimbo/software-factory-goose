import unittest
from unittest.mock import patch
import nuc_unix_admin_canary_quiesce as m
class Quiesce(unittest.TestCase):
 def test_unknown_first_stop_never_reports_success(self):
  approved={'new_pid':10,'new_invocation_id':'a'*32,'new_cgroup_dev':1,'new_cgroup_ino':2}
  with patch.object(m,'plan',return_value=approved),patch.object(m,'live'),patch.object(m.old,'store') as store,patch.object(m.old,'ctl',side_effect=RuntimeError('unknown')) as ctl:
   with self.assertRaisesRegex(RuntimeError,'unknown'):m.apply(approved)
  self.assertEqual(store.call_count,1);self.assertEqual(ctl.call_count,1)
if __name__=='__main__':unittest.main()
