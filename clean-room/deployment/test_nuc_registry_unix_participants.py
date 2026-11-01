import unittest
import nuc_registry_unix_restate_provision as restate
import nuc_registry_v5_unix_unit_upgrade as sdk
class FixedUnits(unittest.TestCase):
 def test_unix_restate_preserves_exact_data_and_identity(self):
  text=restate.unit().decode();self.assertIn('--node-name sfgoose-private',text);self.assertIn('--base-dir '+str(restate.backup.SOURCE),text);self.assertIn('--config-file '+str(restate.CONFIG),text);self.assertIn('User=sfgoose-journal',text);self.assertEqual(restate.CONF,b'listen-mode = "tcp"\n[admin]\nlisten-mode = "unix"\n')
 def test_only_sdk_restate_dependency_changes(self):
  prior=sdk.guarded.units()[sdk.UNIT];new=sdk.unit();old=b'software-factory-goose-private-restate.service';self.assertEqual(prior.count(old),2);self.assertEqual(new,prior.replace(old,restate.UNIT.encode()));self.assertNotEqual(sdk.BACKUP,sdk.PATH)
