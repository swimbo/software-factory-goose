import unittest
from unittest import mock
import nuc_registry_sidecar_install as m
class RegistryInstallTests(unittest.TestCase):
 def test_unit_paths_are_fixed_distinct_and_capability_empty(self):
  units=m.units();self.assertEqual(len(units),5);joined=b'\n'.join(units.values()).decode()
  self.assertIn('registry-launch-grant.sock',joined);self.assertIn('private-registry-sidecar',joined);self.assertIn('CapabilityBoundingSet=',joined);self.assertIn('Group=sfgoose-control',joined);self.assertNotIn('private-real-sidecar',joined)
 def test_changed_plan_cannot_write(self):
  with mock.patch.object(m,'plan',return_value={'x':1}),mock.patch.object(m.old,'store') as store:
   with self.assertRaises(RuntimeError):m.apply({'x':2})
   store.assert_not_called()
if __name__=='__main__':unittest.main()
