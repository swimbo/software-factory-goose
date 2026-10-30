import pathlib,unittest
from unittest import mock
import nuc_backup_copy_cap_canary as canary
class CopyCanaryTests(unittest.TestCase):
 def test_pinned_source_and_disjoint_scope(self):
  raw=(pathlib.Path(__file__).parent/'nuc_restate_backup_tree.py').read_bytes()
  with mock.patch.object(canary,'SOURCE',raw),mock.patch.object(canary.os,'geteuid',return_value=0),mock.patch.object(canary.os,'getegid',return_value=0),mock.patch.object(canary,'capabilities',return_value={'fowner':False}),mock.patch.object(canary.old,'directory'),mock.patch.object(canary.os.path,'lexists',return_value=False):
   plan=canary.plan();self.assertFalse(plan['production_data']);self.assertEqual(plan['root'],str(canary.ROOT))
   with mock.patch.object(canary,'SOURCE',raw+b'changed'),self.assertRaisesRegex(RuntimeError,'source mismatch'):canary.plan()
 def test_owner_capability_is_rejected(self):
  with mock.patch.object(canary.pathlib.Path,'read_text',return_value='CapEff:\t000000000004000b\n'):
   with self.assertRaisesRegex(RuntimeError,'capability profile'):canary.capabilities()
if __name__=='__main__':unittest.main()
