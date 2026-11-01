import json,types,unittest
from unittest import mock
import nuc_registry_restore_history as history
from test_nuc_registry_replay_coordinator import Coordinator
class HistorySupervisorTests(unittest.TestCase):
 def test_expanded_scope_keeps_prior_targets_and_adds_intake(self):
  manifest,configs=Coordinator().fixture();reader=lambda name:configs[name]
  original=history.replay.derive_targets(manifest,reader);expanded=history.derive_restore_targets(manifest,reader)
  self.assertEqual(len(original),12);self.assertEqual(len(expanded),16)
  self.assertTrue(all(item in expanded for item in original));self.assertEqual(sum(x['service']=='IntakeJournal' for x in expanded),4)
  with self.assertRaisesRegex(RuntimeError,'config changed'):history.derive_restore_targets(manifest,lambda _:b'{}')
 def test_forged_target_and_bad_hash_are_refused(self):
  targets=[{'service':'WorkerQueueJournal','key':'queue_1'}]
  def invoke(result):
   p=types.SimpleNamespace(returncode=0,stdout=json.dumps(result).encode(),stderr=b'')
   with mock.patch.object(history.subprocess,'run',return_value=p),mock.patch.object(history.old,'ctl',side_effect=['0','']):return history.invoke('fixed.service','before',[1,2],'anchor.service',targets)
  valid={'schema':1,'histories':[{'service':'WorkerQueueJournal','key':'queue_1','rows':[],'invocations':['a'*64]}]}
  self.assertEqual(invoke(valid),valid)
  for change in ({'schema':1,'histories':[{'service':'WorkerQueueJournal','key':'queue_other','rows':[],'invocations':[]}]},{'schema':1,'histories':[{'service':'WorkerQueueJournal','key':'queue_1','rows':[],'invocations':['not-a-hash']}]}):
   with self.subTest(change=change),self.assertRaises(RuntimeError):invoke(change)
if __name__=='__main__':unittest.main()
