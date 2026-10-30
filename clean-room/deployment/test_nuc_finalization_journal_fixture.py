import pathlib,sys,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_finalization_journal_fixture as fixture

class FinalizationFixtureTests(unittest.TestCase):
    def test_unpinned_sdk_refuses_before_host_effect(self):
        with mock.patch.object(fixture,'SDK_SHA',''), mock.patch.object(fixture.os,'geteuid',return_value=0), mock.patch.object(fixture.os,'getegid',return_value=0), mock.patch.object(fixture.auth,'pin') as pin:
            with self.assertRaisesRegex(RuntimeError,'SDK binary pin not supplied'): fixture.plan()
            pin.assert_not_called()

    def test_sdk_identity_is_recorded_before_changed_database_rejected(self):
        info={'LoadState':'loaded','ActiveState':'active','User':'2000','Group':'2000','NoNewPrivileges':'yes','InvocationID':'a'*32,'MainPID':'42','ExecStart':'{ path='+str(fixture.SDK)+' ; argv[]='+str(fixture.SDK)+' 127.0.0.1:48291 ; code=(null) }'}
        with mock.patch.object(fixture,'run'), mock.patch.object(fixture,'unit_info',return_value=info), mock.patch.object(fixture,'verify_process'), mock.patch.object(fixture.auth,'create') as create, mock.patch.object(fixture,'attest_pg',return_value={'pid':2}):
            with self.assertRaisesRegex(RuntimeError,'postgres identity changed'):fixture.launch_sdk(fixture.UNIT,fixture.UNIT_RECORD,{'pid':1},'synthetic')
            create.assert_called_once()

    def test_identity_transition_is_polled_after_record(self):
        info={'LoadState':'loaded','ActiveState':'active','User':'2000','Group':'2000','NoNewPrivileges':'yes','InvocationID':'b'*32,'MainPID':'42','ExecStart':'{ path='+str(fixture.SDK)+' ; argv[]='+str(fixture.SDK)+' 127.0.0.1:48291 ; code=(null) }'}
        with mock.patch.object(fixture,'run'), mock.patch.object(fixture,'unit_info',return_value=info), mock.patch.object(fixture,'verify_process',side_effect=[RuntimeError('transition'),None]) as verify, mock.patch.object(fixture.auth,'create') as create, mock.patch.object(fixture,'attest_pg',return_value={'pid':1}), mock.patch.object(fixture.time,'sleep'):
            fixture.launch_sdk(fixture.UNIT,fixture.UNIT_RECORD,{'pid':1},'synthetic')
            self.assertEqual(verify.call_count,2);create.assert_called_once()

    def test_attestation_rejects_malformed_response(self):
        with mock.patch.object(fixture.subprocess,'run',return_value=mock.Mock(returncode=0,stdout=b'{"schema":1}',stderr=b'')):
            with self.assertRaisesRegex(RuntimeError,'postgres attestation invalid'):fixture.attest_pg('unused')

if __name__=='__main__':unittest.main()
