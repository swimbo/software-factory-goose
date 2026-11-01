import contextlib,pathlib,sys,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_root_finalization_activate as activate

class ActivationGateTests(unittest.TestCase):
    def test_missing_sdk_admission_fails_before_effects(self):
        with mock.patch.object(activate.gate,'admission',return_value=contextlib.nullcontext()),mock.patch.object(activate.os,'geteuid',return_value=0),mock.patch.object(activate.os,'getegid',return_value=0),mock.patch.object(activate.attest.old,'ctl') as ctl,mock.patch.object(activate.auth,'create') as create:
            with self.assertRaisesRegex(RuntimeError,'retirement proof unavailable'):activate.apply({})
            ctl.assert_not_called();create.assert_not_called()
    def test_pin_without_live_provenance_still_fails_before_effects(self):
        with mock.patch.object(activate.sdk5,'PRODUCER_SHA256','a'*64),mock.patch.object(activate.admission,'verify',side_effect=RuntimeError('live provenance denied')),mock.patch.object(activate.gate,'admission',return_value=contextlib.nullcontext()),mock.patch.object(activate.os,'geteuid',return_value=0),mock.patch.object(activate.os,'getegid',return_value=0),mock.patch.object(activate.attest.old,'ctl') as ctl,mock.patch.object(activate.auth,'create') as create:
            with self.assertRaisesRegex(RuntimeError,'live provenance denied'):activate.apply({})
            ctl.assert_not_called();create.assert_not_called()
    def test_plan_binds_independently_verified_admission(self):
        proof={'admission_sha256':'a'*64,'head':{'transition_id':'fixed'}}
        with mock.patch.object(activate.sdk5,'PRODUCER_SHA256','a'*64),mock.patch.object(activate.admission,'verify',return_value=proof),mock.patch.object(activate.preflight,'plan',return_value={'ready':True}),mock.patch.object(activate.os,'geteuid',return_value=0),mock.patch.object(activate.os,'getegid',return_value=0),mock.patch.object(activate.os.path,'lexists',return_value=False):
            self.assertEqual(activate.plan_locked()['sdk5_admission'],proof)
    def test_admission_change_between_plan_and_apply_denies_before_start(self):
        with mock.patch.object(activate.sdk5,'PRODUCER_SHA256','a'*64),mock.patch.object(activate.admission,'verify',side_effect=[{'admission_sha256':'a'*64},{'admission_sha256':'b'*64}]),mock.patch.object(activate.preflight,'plan',return_value={'ready':True}),mock.patch.object(activate.os,'geteuid',return_value=0),mock.patch.object(activate.os,'getegid',return_value=0),mock.patch.object(activate.os.path,'lexists',return_value=False),mock.patch.object(activate.gate,'admission',return_value=contextlib.nullcontext()),mock.patch.object(activate.auth,'create') as create,mock.patch.object(activate.attest.old,'ctl') as ctl:
            approved=activate.plan_locked()
            with self.assertRaisesRegex(RuntimeError,'activation plan changed'):activate.apply(approved)
            create.assert_not_called();ctl.assert_not_called()
if __name__=='__main__':unittest.main()
