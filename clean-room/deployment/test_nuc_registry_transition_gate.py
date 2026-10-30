import fcntl,os,pathlib,tempfile,unittest
from unittest.mock import patch
import nuc_registry_transition_gate as gate
class RegistryGate(unittest.TestCase):
 def setup_gate(self,root):
  root.chmod(0o700);p=root/gate.LOCK;p.write_bytes(b'');p.chmod(0o600)
 def test_shared_admission_excludes_upgrade_and_exclusive_excludes_admission(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);self.setup_gate(root)
   with patch.object(gate,'no_acl'):
    with gate._gate(root,False,os.getuid(),os.getgid()):
     with self.assertRaises(BlockingIOError):
      with gate._gate(root,True,os.getuid(),os.getgid()):pass
    with gate._gate(root,True,os.getuid(),os.getgid()):
     with self.assertRaises(BlockingIOError):
      with gate._gate(root,False,os.getuid(),os.getgid()):pass
 def test_partial_or_symlink_marker_closes_admission(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);self.setup_gate(root)
   with patch.object(gate,'no_acl'):
    (root/gate.MARKER).write_bytes(b'partial')
    with self.assertRaisesRegex(RuntimeError,'transition unresolved'):
     with gate._gate(root,False,os.getuid(),os.getgid()):pass
    (root/gate.MARKER).unlink();(root/gate.MARKER).symlink_to('missing')
    with self.assertRaisesRegex(RuntimeError,'transition unresolved'):
     with gate._gate(root,False,os.getuid(),os.getgid()):pass
 def test_owner_death_keeps_durable_marker_closed(self):
  import signal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);self.setup_gate(root);ready_r,ready_w=os.pipe();hold_r,hold_w=os.pipe();pid=os.fork()
   if pid==0:
    try:
     os.close(ready_r);os.close(hold_w)
     intent={'schema':1,'transition_id':'01ARZ3NDEKTSV4RRFFQ69G5FAV','old_manifest_sha256':'a'*64,'new_manifest_sha256':'b'*64}
     with patch.object(gate,'no_acl'),gate._transition(root,intent,os.getuid(),os.getgid()):
      os.write(ready_w,b'1');os.read(hold_r,1)
    finally:os._exit(0)
   os.close(ready_w);os.close(hold_r)
   try:
    self.assertEqual(os.read(ready_r,1),b'1')
    # The child remains our unreaped direct child and is blocked on our pipe.
    os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);pid=None
    with patch.object(gate,'no_acl'),self.assertRaisesRegex(RuntimeError,'transition unresolved'):
     with gate._gate(root,False,os.getuid(),os.getgid()):pass
   finally:
    os.close(ready_r);os.close(hold_w)
    if pid is not None:os.waitpid(pid,0)
 def test_completion_refuses_without_reviewed_replay_producer(self):
  with patch.object(gate,'REPLAY_PRODUCER_SHA',None),patch.object(gate,'_protected_read') as read:
   with self.assertRaisesRegex(RuntimeError,'replay producer unavailable'):gate.finish_transition(-1,{'transition_id':'01ARZ3NDEKTSV4RRFFQ69G5FAV'})
   read.assert_not_called()
 def test_completion_history_requires_exact_append(self):
  import json
  old={'schema':1,'active_intent':'old','entries':[{'config':'one'}]};new={'schema':1,'active_intent':'new','entries':[{'config':'one'},{'config':'two'}]}
  raw=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode()
  oldraw,newraw=raw(old),raw(new);intent={'old_manifest_sha256':gate._digest(oldraw),'new_manifest_sha256':gate._digest(newraw)}
  replay={'prior_catalog_count':1,'prior_catalogs_sha256':gate._digest(raw(old['entries']))}
  gate.verify_history(oldraw,newraw,intent,replay)
  altered=raw({'schema':1,'active_intent':'new','entries':[{'config':'changed'},{'config':'two'}]})
  with self.assertRaisesRegex(RuntimeError,'history mismatch'):gate.verify_history(oldraw,altered,intent,replay)
 def test_symlink_lock_refused(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);root.chmod(0o700);(root/gate.LOCK).symlink_to('missing')
   with patch.object(gate,'no_acl'),self.assertRaises(OSError):
    with gate._gate(root,False,os.getuid(),os.getgid()):pass
if __name__=='__main__':unittest.main()

class ServerMintedDeployment(unittest.TestCase):
 def test_unknown_registration_cannot_resolve_and_exact_receipt_binds_plan(self):
  import hashlib,json,pathlib
  from unittest.mock import patch
  name='01M66XF6HPWC3NXMAFDHKHDSP7';hist=pathlib.Path('/history')
  plan={'transition_id':name,'new_deployment_id':None,'old_sdk_uri':'http://127.0.0.1:9084','new_sdk_uri':'http://127.0.0.1:9085','new_manifest_sha256':'a'*64}
  raw=json.dumps(plan,sort_keys=True,separators=(',',':')).encode()+b'\n'
  started={'transition_id':name,'plan_sha256':hashlib.sha256(raw).hexdigest(),'new_manifest_sha256':'a'*64,'uri':plan['new_sdk_uri']}
  start=json.dumps(started,sort_keys=True,separators=(',',':')).encode()+b'\n'
  receipt={'schema':1,'transition_id':name,'uri':plan['new_sdk_uri'],'deployment_id':'dp_ABC123','invocation_id':'1'*32,'binding_sha256':hashlib.sha256(start).hexdigest()}
  files={name+'.plan.json':raw,name+'.registration-started.json':start,name+'.registration-complete.json':json.dumps(receipt).encode()}
  def read(path,*_):
   if path.name not in files:raise FileNotFoundError(path)
   return files[path.name]
  with patch.object(gate,'_protected_read',side_effect=read):
   self.assertEqual(gate.resolve_deployment(plan,hist),'dp_ABC123')
   files.pop(name+'.registration-complete.json')
   with self.assertRaises(FileNotFoundError):gate.resolve_deployment(plan,hist)
