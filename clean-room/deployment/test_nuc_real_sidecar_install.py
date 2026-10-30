import unittest
from unittest import mock
import nuc_real_sidecar_install as m
class RealSidecarInstall(unittest.TestCase):
 def test_exact_unit_scope_and_no_canary_path_reuse(self):
  units=m.units();self.assertEqual(len(units),5)
  text=b'\n'.join(units.values()).decode();self.assertIn('Group=sfgoose-control',text);self.assertIn('private-real-sidecar',text);self.assertNotIn('private-grant-sidecar',text);self.assertIn('real-launch-grant.sock',text)
 def test_changed_plan_refuses_before_writes(self):
  with mock.patch.object(m,'plan',return_value={'x':1}),mock.patch.object(m.old,'store') as store:
   with self.assertRaises(RuntimeError):m.apply({'x':2})
   store.assert_not_called()
if __name__=='__main__':unittest.main()
