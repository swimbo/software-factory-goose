import json,types,unittest
from unittest import mock
import nuc_registry_admission_observe as observe
class AdmissionObservationTests(unittest.TestCase):
 def test_journal_nonzero_or_malformed_counts_deny(self):
  value={'schema':1,'admin_dev':1,'admin_ino':2,'old_listeners_and_established_absent':True,'tcp_admin_absent':True,'counts':{'invocations':0,'queue_entries':0,'queues':0}}
  def run(v):
   p=types.SimpleNamespace(returncode=0,stdout=json.dumps(v).encode(),stderr=b'')
   with mock.patch.object(observe.old,'read'),mock.patch.object(observe,'unit_available'),mock.patch.object(observe.subprocess,'run',return_value=p):return observe.run('journal',[1,2],'dp_Test')
  self.assertEqual(run(value),value)
  for counts in ({'invocations':1,'queue_entries':0,'queues':0},{'invocations':False,'queue_entries':0,'queues':0},{'invocations':0,'queue_entries':0}):
   with self.subTest(counts=counts),self.assertRaises(RuntimeError):run({**value,'counts':counts})
 def test_deny_requires_explicit_eacces_result(self):
  p=types.SimpleNamespace(returncode=0,stdout=b'{"schema":1,"admin_access_denied":false}',stderr=b'')
  with mock.patch.object(observe.old,'read'),mock.patch.object(observe,'unit_available'),mock.patch.object(observe.subprocess,'run',return_value=p):
   with self.assertRaisesRegex(RuntimeError,'denial unavailable'):observe.run('deny',[1,2])
if __name__=='__main__':unittest.main()
