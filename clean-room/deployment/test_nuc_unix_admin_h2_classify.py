import hashlib,json,pathlib,sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tests'/'fixtures'))
import nuc_unix_admin_h2_classify as c

def enc(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'
class FixedClassification(unittest.TestCase):
 def test_forwarded_completed_is_not_reported_as_no_old_effect(self):
  epoch='a'*64;old='dp_old';before={'epoch_sha256':epoch,'hold':'i1','queued':'i2'};before_raw=enc(before)
  base={'epoch_sha256':epoch,'old_deployment_id':old,'probe_receipt_sha256':hashlib.sha256(before_raw).hexdigest()}
  after={'epoch_sha256':epoch,'stage':'after_retirement','effect':'requires journal inspection','old_connection_denied':True,'new_connection_denied':True,'probe_terminal':True,'forwarded':'i4'}
  hold={'id':'i1','target_service_name':'FenceFixture','target_service_key':'blocked','target_handler_name':'hold','status':'suspended','pinned_deployment_id':old}
  queue={'id':'i2','target_service_name':'FenceFixture','target_service_key':'blocked','target_handler_name':'increment','status':'inboxed','pinned_deployment_id':None}
  delay={'id':'i3','target_service_name':'FenceFixture','target_service_key':'delayed','target_handler_name':'increment','status':'scheduled','pinned_deployment_id':None}
  forward={'id':'i4','target_service_name':'FenceFixture','target_service_key':'after','target_handler_name':'increment','status':'pending','pinned_deployment_id':None}
  q=[{'entry_id':x,'entry_kind':'invocation','deployment':None} for x in ('i1','i2')]
  def snapshot(f):return {'schema':1,'role':'postretire','epoch_sha256':epoch,'result':{'operation':'snapshot','rows':{'invocations':[hold,queue,delay,f],'queue':q,'state':[{'service_key':'history','key':'count','value_utf8':'1'}]}}}
  entries={c.BEFORE.name:before_raw,c.REG.name:enc({'operation':'register-old','deployment_id':old}),c.JOURNAL_BEFORE.name:enc(base),c.AFTER.name:enc(after),'unix-admin-h2-canary-snapshot-postretire-complete.json':enc(snapshot(forward))}
  def read(path,*args,**kwargs):return entries[path.name]
  with patch.object(c,'ROLE','postretire'),patch.object(c.os,'geteuid',return_value=0),patch.object(c.os.path,'lexists',return_value=False),patch.object(c.probe,'epoch',return_value=epoch),patch.object(c.old,'read',side_effect=read):
   self.assertEqual(c.plan()['classification'],{'forwarded':'retained-nonterminal','old_effect':'absent'})
   entries['unix-admin-h2-canary-snapshot-postretire-complete.json']=enc(snapshot({**forward,'status':'completed'}))
   with self.assertRaises(RuntimeError):c.plan()
