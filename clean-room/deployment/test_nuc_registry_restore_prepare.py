import contextlib
import unittest
from unittest import mock
import nuc_registry_restore_prepare as restore

class RestorePrepareTests(unittest.TestCase):
 def test_units_use_distinct_namespace_unix_admin_and_copy(self):
  units=restore.units();self.assertEqual(set(units),{restore.NET,restore.SERVER})
  server=units[restore.SERVER].decode()
  self.assertIn('PrivateNetwork=yes',server);self.assertIn('JoinsNamespaceOf='+restore.NET,server)
  self.assertIn('ReadWritePaths='+str(restore.DATA),server)
  self.assertNotIn('ReadWritePaths='+str(restore.backup.SOURCE),server)
  self.assertIn('--node-name sfgoose-private',server)
  self.assertIn(b'listen-mode = "unix"',restore.CONFIG)
 def test_mismatched_copy_never_installs_units_or_publishes_completion(self):
  events=[];reviewed={'manifest_sha256':'0'*64,'preservation':{}}
  @contextlib.contextmanager
  def locked():yield
  with mock.patch.object(restore.backup,'locked',locked),mock.patch.object(restore,'plan_locked',return_value=reviewed),mock.patch.object(restore.old,'store',side_effect=lambda p,*a:events.append(p)),mock.patch.object(restore.old,'syncdir'),mock.patch.object(restore.old,'directory'),mock.patch.object(restore.os,'mkdir'),mock.patch.object(restore.os,'chmod'),mock.patch.object(restore.os,'chown'),mock.patch.object(restore.os,'open',return_value=11),mock.patch.object(restore.os,'close'),mock.patch.object(restore.tree,'copy_tree',return_value={'unexpected':True}),mock.patch.object(restore.retirement,'capture_transport'),mock.patch.object(restore.old,'ctl') as ctl:
   with self.assertRaisesRegex(RuntimeError,'copy differs'):restore.apply(reviewed)
  self.assertEqual(events,[restore.START]);ctl.assert_not_called()
if __name__=='__main__':unittest.main()
