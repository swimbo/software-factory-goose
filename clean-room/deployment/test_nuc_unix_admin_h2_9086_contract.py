"""Regression checks for the distinct synthetic 9086 recovery contract."""
import pathlib,sys,unittest
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parent/'tests'/'fixtures'))
import nuc_unix_admin_h2_9086_orchestrator as orchestration
import nuc_unix_admin_h2_9086_install as sdk
import nuc_unix_admin_h2_9086_helpers_install as helpers
class ContractTests(unittest.TestCase):
 def test_fixed_sequence_never_replays_9082(self):
  self.assertEqual(orchestration.STAGES,['epoch3','bind_retained_data','start_9086','prezero_9086','dispatch_once_9086','reconcile_9086','restart_restate','snapshot_afterrestart','observe_history_afterrestart','classify_afterrestart','quiesce'])
  self.assertNotIn('9082',sdk.UNIT);self.assertNotEqual(helpers.QUERY,helpers.LOST)
 def test_empty_or_changed_source_manifest_refused_before_effect(self):
  with patch.object(orchestration.os,'geteuid',return_value=0),patch.object(orchestration.os.path,'lexists',return_value=False),patch.object(orchestration,'SOURCE_HASHES',{}):
   with self.assertRaisesRegex(RuntimeError,'source manifest'):orchestration.plan()
if __name__=='__main__':unittest.main()
