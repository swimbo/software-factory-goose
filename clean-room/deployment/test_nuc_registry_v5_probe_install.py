import unittest
from unittest import mock
import nuc_registry_v5_probe_install as install

class V5ProbeInstallerTests(unittest.TestCase):
 def test_nonroot_denied_before_read_or_write(self):
  with mock.patch.object(install.os,'geteuid',return_value=1000),mock.patch.object(install,'read_source') as source:
   with self.assertRaisesRegex(RuntimeError,'root required'):install.plan()
   source.assert_not_called()
 def test_copy_failure_retains_intent_and_does_not_create_completion(self):
  reviewed={'schema':1}
  with mock.patch.object(install,'plan',return_value=reviewed),mock.patch.object(install,'read_source',return_value=b'synthetic'),mock.patch.object(install.auth,'create',side_effect=[None,RuntimeError('copy failed')]) as create:
   with self.assertRaisesRegex(RuntimeError,'copy failed'):install.apply(reviewed)
   self.assertEqual(create.call_count,2);self.assertEqual(create.call_args_list[0].args[0],install.INTENT)
if __name__=='__main__':unittest.main()
