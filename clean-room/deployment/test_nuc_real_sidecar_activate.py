import json,unittest
from unittest import mock
import nuc_real_sidecar_activate as m
class RealActivationTests(unittest.TestCase):
 def test_plan_mismatch_cannot_write_or_register(self):
  with mock.patch.object(m,'plan',return_value={'x':1}),mock.patch.object(m.old,'store') as store,mock.patch.object(m.old,'ctl') as ctl:
   with self.assertRaises(RuntimeError):m.apply({'x':2})
   store.assert_not_called();ctl.assert_not_called()
 def test_journal_registration_uses_persisted_invocation(self):
  line=json.dumps({'MESSAGE':'REAL_REGISTRATION '+json.dumps({'id':'dp_good','service_count':4}),'_SYSTEMD_UNIT':m.install.NAME+'register.service','_SYSTEMD_INVOCATION_ID':'a'*32}).encode()
  with mock.patch.object(m.subprocess,'run') as run:
   run.return_value.stdout=line;run.return_value.stderr=b''
   self.assertEqual(m.registration()['invocation_id'],'a'*32)
   run.return_value.stdout=line+b'\n'+line
   with self.assertRaises(RuntimeError):m.registration()
if __name__=='__main__':unittest.main()
