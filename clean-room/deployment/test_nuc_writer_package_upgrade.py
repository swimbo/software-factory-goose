import contextlib,unittest
from unittest.mock import patch
import nuc_writer_package_upgrade as m
class Upgrade(unittest.TestCase):
 def test_changed_plan_fails_before_intent(self):
  with patch.object(m.prior,'generations',return_value=['x']),patch.object(m.prior,'locks',return_value=contextlib.nullcontext()),patch.object(m,'snapshot',return_value={'generations':['x'],'boot_id':'new'}),patch.object(m.old,'store') as store:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):m.apply({'generations':['x'],'boot_id':'old'})
   store.assert_not_called()
if __name__=='__main__':unittest.main()
