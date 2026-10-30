import hashlib
import pathlib
import unittest
from unittest.mock import patch
import nuc_openfile_canary_install as c

HERE=pathlib.Path(__file__).parent
class Installer(unittest.TestCase):
    def test_candidate_source_hashes_match_plan(self):
        self.assertEqual(hashlib.sha256((HERE/'nuc_openfile_public_canary.py').read_bytes()).hexdigest(),c.PROGRAM_SHA)
        self.assertEqual(hashlib.sha256((HERE/'units/openfile-public-canary.service.in').read_bytes()).hexdigest(),c.UNIT_SHA)
    def test_changed_review_cannot_create_anything(self):
        with patch.object(c,'plan',return_value=({'boot_id':'expected'},b'public',b'unit')),patch.object(c.os,'mkdir') as mkdir,patch.object(c,'create') as create:
            with self.assertRaises(RuntimeError):c.apply({'boot_id':'different'})
            mkdir.assert_not_called();create.assert_not_called()
    def test_exact_plan_only_creates_fixed_files_no_service_start(self):
        spec={'network_device':1,'network_inode':2}
        with patch.object(c,'plan',return_value=(spec,b'public',b'unit')),patch.object(c.os,'mkdir') as mkdir,patch.object(c,'create') as create,patch.object(c,'syncdir'):
            self.assertEqual(c.apply(spec)['status'],'installed_not_started')
            self.assertEqual(mkdir.call_count,2)
            self.assertEqual({str(call.args[0]) for call in create.call_args_list}, {str(c.LEDGER/'intent.json'),str(c.LEDGER/'receipt.json'),str(c.PUBLIC_DIR/'public'),str(c.PUBLIC_DIR/'expected'),str(c.PROGRAM),str(c.UNIT)})

if __name__=='__main__':unittest.main()
