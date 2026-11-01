import json,pathlib,types,unittest
from unittest.mock import patch
import nuc_registry_pending_admission as pending

class PendingAdmissionTests(unittest.TestCase):
 def setUp(self):
  self.digest='a'*64;self.intent={'transition_id':'01ARZ3NDEKTSV4RRFFQ69G5FAV','new_manifest_sha256':'b'*64};self.replay={'deployment_id':'dp_abc','attestation_sha256':'c'*64};self.att={'netns_dev':1,'netns_ino':2};self.boot='boot';self.raw=b'receipt';self.marker=json.dumps(self.intent).encode();self.package=json.dumps({'schema':1,'installed':True,'executed':False,'activated':False,'launcher_sha256':self.digest}).encode()
  def read(path,*args):
   if path==pending.PACKAGE:return self.package
   if path==pending.LAUNCHER:return b'launcher'
   if path==pending.RECEIPT:return self.raw
   if path.name.endswith('unix-restate-activation-complete.json'):return b'{"socket_dev":3,"socket_ino":4}'
   if path.name=='transition.json':return self.marker
   raise FileNotFoundError(path)
  def require(ok,msg):
   if not ok:raise RuntimeError(msg)
  self.gate=types.SimpleNamespace(_protected_read=read,_json=json.loads,_digest=lambda raw:self.digest if raw==b'launcher' else 'd'*64,require=require,ROOT=pathlib.Path('/gate'),MARKER='transition.json')
  self.result={'schema':1,'admission_sha256':'d'*64,'transition_id':self.intent['transition_id'],'manifest_sha256':self.intent['new_manifest_sha256'],'attestation_sha256':self.replay['attestation_sha256'],'boot_id':self.boot,'transition_still_closed':True}
 def run_verify(self,stdout=None,returncode=0):
  result=types.SimpleNamespace(returncode=returncode,stdout=json.dumps(self.result if stdout is None else stdout).encode(),stderr=b'')
  with patch.object(pending,'LAUNCHER_SHA256',self.digest),patch.object(pending.contract,'validate') as validate,patch.object(pending.subprocess,'run',return_value=result):
   pending.verify(self.gate,self.intent,self.replay,self.att,self.boot)
   self.assertEqual(validate.call_args.args[1]['admin_socket_ino'],4)
 def test_valid_pending_proof(self):self.run_verify()
 def test_missing_pin_denied(self):
  with patch.object(pending,'LAUNCHER_SHA256',None),self.assertRaisesRegex(RuntimeError,'producer unavailable'):pending.verify(self.gate,self.intent,self.replay,self.att,self.boot)
 def test_extra_live_field_denied(self):
  with self.assertRaisesRegex(RuntimeError,'live proof unavailable'):self.run_verify({**self.result,'extra':True})
 def test_crashed_producer_denied(self):
  with self.assertRaisesRegex(RuntimeError,'live proof unavailable'):self.run_verify(returncode=1)
 def test_unpublished_receipt_denied(self):
  original=self.gate._protected_read
  def missing(path,*args):
   if path==pending.RECEIPT:raise FileNotFoundError(path)
   return original(path,*args)
  self.gate._protected_read=missing
  with self.assertRaises(FileNotFoundError):self.run_verify()

class FinishFenceTests(unittest.TestCase):
 def test_pending_proof_crash_prevents_all_commit_effects(self):
  import os
  import nuc_registry_transition_gate as gate
  ident='01ARZ3NDEKTSV4RRFFQ69G5FAV';boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() if pathlib.Path('/proc/sys/kernel/random/boot_id').exists() else 'mac-test'
  encode=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode()
  oldraw=encode({'schema':1,'active_intent':'old','entries':[{'x':1}]});newraw=encode({'schema':1,'active_intent':'new','entries':[{'x':1},{'x':2}]})
  intent={'schema':1,'transition_id':ident,'old_manifest_sha256':gate._digest(oldraw),'new_manifest_sha256':gate._digest(newraw)};marker=encode(intent);att=encode({'boot_id':boot,'config_sha256':intent['new_manifest_sha256']});producer=b'producer';probe=b'probe'
  plan={'transition_id':ident,'old_manifest_sha256':intent['old_manifest_sha256'],'new_manifest_sha256':intent['new_manifest_sha256']};planraw=encode(plan)
  replay={'schema':1,'transition_id':ident,'old_manifest_sha256':intent['old_manifest_sha256'],'new_manifest_sha256':intent['new_manifest_sha256'],'prior_catalogs_sha256':gate._digest(encode([{'x':1}])),'prior_catalog_count':1,'replayed_catalog_count':1,'deployment_id':'dp_ABC','attestation_sha256':gate._digest(att),'producer_sha256':gate._digest(producer),'plan_sha256':gate._digest(planraw)}
  files={'transition.json':marker,ident+'.replay.json':encode(replay),ident+'.plan.json':planraw,ident+'.old-registry.json':oldraw,'registry.json':newraw,'attest.json':att,'probe':probe,'producer':producer}
  def read(path,*args):return files[path.name]
  fake=types.SimpleNamespace(returncode=0,stdout=b'{"service_attested":true,"grant_requested":false}',stderr=b'')
  actual_read=pathlib.Path.read_text
  def path_read(path,*args,**kwargs):
   if str(path)=='/proc/sys/kernel/random/boot_id':return boot
   return actual_read(path,*args,**kwargs)
  with patch.object(gate,'REPLAY_PRODUCER_SHA',gate._digest(producer)),patch.object(gate,'REPLAY_PRODUCER',pathlib.Path('/producer')),patch.object(gate,'REGISTRY',pathlib.Path('/registry.json')),patch.object(gate,'_protected_read',side_effect=read),patch.object(gate,'_directory',side_effect=lambda *a:os.open('/dev/null',os.O_RDONLY)),patch.object(gate,'resolve_deployment',return_value='dp_ABC'),patch.object(gate,'registry_profile',return_value={'profile':'sdk5','attestation':pathlib.Path('/attest.json'),'probe':pathlib.Path('/probe'),'probe_sha256':gate._digest(probe)}),patch.object(pathlib.Path,'read_text',path_read),patch('subprocess.run',return_value=fake),patch.object(pending,'verify',side_effect=RuntimeError('observer crashed')),patch.object(gate,'_store_history') as history,patch.object(gate,'_atomic_head') as head,patch.object(os,'unlink') as unlink:
   with self.assertRaisesRegex(RuntimeError,'observer crashed'):gate.finish_transition(-1,intent)
   history.assert_not_called();head.assert_not_called();unlink.assert_not_called()

if __name__=='__main__':unittest.main()
