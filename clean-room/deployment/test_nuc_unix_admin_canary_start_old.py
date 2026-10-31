import unittest
from unittest.mock import patch
import nuc_unix_admin_canary_start_old as m
class StartOld(unittest.TestCase):
 def test_changed_plan_never_starts(self):
  with patch.object(m,'plan',return_value={'revision':2}),patch.object(m.old,'store') as store,patch.object(m.old,'ctl') as ctl:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):m.apply({'revision':1})
   store.assert_not_called();ctl.assert_not_called()
if __name__=='__main__':unittest.main()
