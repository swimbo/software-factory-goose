import contextlib
import unittest
from unittest import mock
import nuc_registry_offline_backup as backup

class OfflineBackupTests(unittest.TestCase):
 def test_uncertain_stop_keeps_intent_and_does_not_copy_or_publish(self):
  events=[];plan={'restate':{},'preservation':{'external':{}}}
  @contextlib.contextmanager
  def locked():events.append('lock');yield
  def store(path,data,mode):events.append(('store',path))
  def ctl(*args):
   if args[0]=='stop':raise RuntimeError('uncertain stop')
  with mock.patch.object(backup,'locked',locked),mock.patch.object(backup,'plan_locked',return_value=plan),mock.patch.object(backup.old,'store',side_effect=store),mock.patch.object(backup.old,'directory'),mock.patch.object(backup.old,'ctl',side_effect=ctl),mock.patch.object(backup.os.path,'lexists',return_value=True),mock.patch.object(backup,'verify_loaded_fence'),mock.patch.object(backup.retirement,'assert_original'),mock.patch.object(backup.retirement.external,'collect_with_transport',return_value=({}, {'id':'fixture'})),mock.patch.object(backup.tree,'copy_tree') as copy:
   with self.assertRaisesRegex(RuntimeError,'uncertain stop'):backup.apply(plan)
  self.assertLess(events.index(('store',backup.START)),events.index(('store',backup.FENCE)))
  self.assertNotIn(('store',backup.DONE),events);copy.assert_not_called()
if __name__=='__main__':unittest.main()
