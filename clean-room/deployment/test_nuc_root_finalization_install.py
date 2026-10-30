import pathlib,sys,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_root_finalization_install as install

class FinalizationInstallTests(unittest.TestCase):
    def test_unpinned_plan_refuses_before_filesystem_access(self):
        with mock.patch.object(install,'RUNTIME_SHA',''), mock.patch.object(install,'PUBLISHER_SHA',''), mock.patch.object(install.os,'geteuid',return_value=0), mock.patch.object(install.os,'getegid',return_value=0), mock.patch.object(install.guard,'ancestors') as ancestors:
            with self.assertRaisesRegex(RuntimeError,'binaries not pinned'):install.plan()
            ancestors.assert_not_called()
    def test_failed_copy_leaves_intent_and_does_not_create_lock_or_socket(self):
        reviewed={'schema':1}
        with mock.patch.object(install,'plan',return_value=reviewed), mock.patch.object(install,'source',return_value=b'fixture'), mock.patch.object(install.auth,'create',side_effect=[None,RuntimeError('copy failed')]) as create, mock.patch.object(install.os,'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError,'copy failed'):install.apply(reviewed)
            self.assertEqual(create.call_args_list[0].args[0],install.INTENT)
            mkdir.assert_not_called()

if __name__=='__main__':unittest.main()
