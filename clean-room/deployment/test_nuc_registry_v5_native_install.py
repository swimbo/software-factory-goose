import unittest
from unittest import mock
import nuc_registry_v5_grant_install as grant
import nuc_registry_v5_launch_install as launch
class NativeInstall(unittest.TestCase):
 def test_distinct_sdk5_paths_and_exact_build_pins(self):
  self.assertEqual(grant.TARGET.name,'registry-v5-grant-prepare');self.assertEqual(launch.TARGET.name,'root-launch-v5')
  self.assertEqual(grant.STAGE,launch.STAGE);self.assertNotEqual(grant.SHA,launch.SHA)
 def test_nonroot_denied_before_stage_read(self):
  for m in (grant,launch):
   with self.subTest(module=m.__name__),mock.patch.object(m.os,'geteuid',return_value=1000),mock.patch.object(m,'read_source') as read:
    with self.assertRaisesRegex(RuntimeError,'root required'):m.plan()
    read.assert_not_called()
 def test_failed_copy_retains_intent_without_completion(self):
  for m in (grant,launch):
   with self.subTest(module=m.__name__),mock.patch.object(m,'plan',return_value={'schema':1}),mock.patch.object(m,'read_source',return_value=b'synthetic'),mock.patch.object(m.auth,'create',side_effect=[None,RuntimeError('copy failed')]) as create:
    with self.assertRaisesRegex(RuntimeError,'copy failed'):m.apply({'schema':1})
    self.assertEqual([x.args[0] for x in create.call_args_list],[m.INTENT,m.TARGET])
