import json,unittest
from unittest.mock import patch
import nuc_unix_admin_h2_probe_after_recovery as r
class Terminal(unittest.TestCase):
 def test_only_exact_pid1_success_is_accepted(self):
  b=b'root before receipt';record={'MESSAGE_ID':'7ad2d189f7e94e70a38c781354912448','UNIT':r.before.UNIT,'_PID':'1','exact_invocation':True};j={'schema':1,'before_sha256':r.hashlib.sha256(b).hexdigest(),'query_complete':True,'matching_pid1_records':[record]}
  with patch.object(r.old,'read',side_effect=lambda *a,**k:json.dumps(j).encode()),patch.object(r.old,'ctl',return_value=''),patch.object(r.pathlib.Path,'exists',return_value=False):
   with patch.object(r.old,'ctl',side_effect=lambda *a:'0' if a[3]=='MainPID' else ''):
    r.terminal(b)
    for patch_value in ({'exact_invocation':False},{'MESSAGE_ID':'other'},{'_PID':'2'}):
     j['matching_pid1_records']=[dict(record,**patch_value)]
     with self.subTest(patch_value=patch_value),self.assertRaises(RuntimeError):r.terminal(b)
    j['matching_pid1_records']=[record];j['query_complete']=False
    with self.assertRaises(RuntimeError):r.terminal(b)
