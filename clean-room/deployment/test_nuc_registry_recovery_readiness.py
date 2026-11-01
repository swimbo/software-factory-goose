import contextlib,json,types,unittest
from unittest import mock
import nuc_registry_recovery_readiness as readiness
class RecoveryReadinessTests(unittest.TestCase):
 def test_plan_uses_actual_command_and_destination_sizing(self):
  head={'schema':1};restate={'ExecStart':'fixed'};sizing={'logical_bytes':100,'required_bytes':2147484048,'destination_dev':7,'destination_ino':8};cap={'public_copy_equal':True,'restore_equal':True,'no_fowner':True,'production_data':False}
  def read(path,*args,**kwargs):return json.dumps(cap).encode() if path==readiness.backup.cap_canary.DONE else b'probe'
  with mock.patch.object(readiness.os,'geteuid',return_value=0),mock.patch.object(readiness.os.path,'lexists',return_value=False),mock.patch.object(readiness.gate,'admission',contextlib.nullcontext),mock.patch.object(readiness.gate,'verify_head',return_value=head),mock.patch.object(readiness.pinned,'verify',return_value={'sha256':'a'*64}),mock.patch.object(readiness.old,'read',side_effect=read),mock.patch.object(readiness.retired,'observe',return_value=restate),mock.patch.object(readiness.backup,'validate_active_restate') as command,mock.patch.object(readiness.inventory,'inspect',return_value=sizing) as inspect,mock.patch.object(readiness.old,'ctl',return_value='not-found'),mock.patch.object(readiness.subprocess,'run',return_value=types.SimpleNamespace(stdout=b'/etc/systemd/system\n')):
   result=readiness.plan()
  command.assert_called_once_with(restate);inspect.assert_called_once_with(readiness.backup.SOURCE,readiness.backup.DEST.parent);self.assertEqual(result['source_sizing'],sizing)
 def test_insufficient_destination_capacity_does_not_publish(self):
  cap={'public_copy_equal':True,'restore_equal':True,'no_fowner':True,'production_data':False}
  with mock.patch.object(readiness.os,'geteuid',return_value=0),mock.patch.object(readiness.os.path,'lexists',return_value=False),mock.patch.object(readiness.gate,'admission',contextlib.nullcontext),mock.patch.object(readiness.gate,'verify_head',return_value={}),mock.patch.object(readiness.pinned,'verify',return_value={}),mock.patch.object(readiness.old,'read',return_value=json.dumps(cap).encode()),mock.patch.object(readiness.retired,'observe',return_value={}),mock.patch.object(readiness.backup,'validate_active_restate'),mock.patch.object(readiness.inventory,'inspect',side_effect=RuntimeError('insufficient backup/restore capacity')),mock.patch.object(readiness.old,'store') as store:
   with self.assertRaisesRegex(RuntimeError,'insufficient'):readiness.apply({})
  store.assert_not_called()
if __name__=='__main__':unittest.main()
