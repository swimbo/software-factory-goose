import unittest
from unittest.mock import patch
import nuc_registry_gate_install as m
class Bootstrap(unittest.TestCase):
 def test_changed_plan_is_refused_before_any_creation(self):
  with patch.object(m,'plan',return_value={'boot_id':'new'}),patch.object(m.old,'store') as store,patch.object(m.os,'mkdir') as mkdir:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):m.apply({'boot_id':'old'})
   store.assert_not_called();mkdir.assert_not_called()
 def test_existing_gate_denied_before_reading_registry(self):
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.os.path,'lexists',return_value=True),patch.object(m.old,'read') as read:
   with self.assertRaisesRegex(RuntimeError,'already attempted'):m.plan()
   read.assert_not_called()
if __name__=='__main__':unittest.main()
