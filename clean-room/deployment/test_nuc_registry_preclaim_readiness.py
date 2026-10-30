import tempfile,pathlib,unittest
from unittest.mock import patch
import nuc_registry_preclaim_readiness as m

class Readiness(unittest.TestCase):
 def test_unattested_registry_never_reaches_helper(self):
  active={'intent_id':'01M65RMR3F04YB1B016EBBSXGG','task_id':'01M65RMR3F04YB1B016EBBSXGG','generation':'01M65RMR3F04YB1B016EBBSXGG','catalog_sha256':'a'*64,'registry_validated':True,'capabilities_empty':True,'grant_requested':False}
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m,'run_json',side_effect=[active,{'service_attested':False,'grant_requested':False}]),patch.object(m.old,'read') as read:
   with self.assertRaisesRegex(RuntimeError,'not attested'):m.plan()
   read.assert_not_called()
 def test_native_capability_or_registry_failure_denied_before_attestor(self):
  active={'intent_id':'x','task_id':'x','generation':'01M65RMR3F04YB1B016EBBSXGG','catalog_sha256':'a'*64,'registry_validated':True,'capabilities_empty':False,'grant_requested':False}
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m,'run_json',return_value=active) as probe:
   with self.assertRaisesRegex(RuntimeError,'registry identity unavailable'):m.plan()
   self.assertEqual(probe.call_count,1)
 def test_only_exact_empty_lifecycle_lock_allowed(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(m,'STATE',pathlib.Path(tmp)),patch.object(m.old,'read',return_value=b'') as read:
   g='generation';lock=pathlib.Path(tmp)/(g+'.callback-lifecycle.lock');lock.touch();m.check_no_effects(g);read.assert_called_once_with(lock,0o600,maxsize=0)
   (pathlib.Path(tmp)/(g+'.host-create-intent.json')).touch()
   with self.assertRaisesRegex(RuntimeError,'already has effects'):m.check_no_effects(g)
   (pathlib.Path(tmp)/(g+'.host-create-intent.json')).unlink();lock.unlink()
   with self.assertRaisesRegex(RuntimeError,'lifecycle lock missing'):m.check_no_effects(g)
if __name__=='__main__':unittest.main()
