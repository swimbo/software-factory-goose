import copy,hashlib,json,pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_registry_v5_manifest_candidate as m
import nuc_registry_attestation_profiles as p
class CandidateTests(unittest.TestCase):
 def setUp(self):
  self.e=b'protected evidence';self.old={'schema':1,'active_intent':p.SDK4['intent'],'entries':[{'config':p.SDK4['config'],'evidence':'old.json','evidence_sha256':hashlib.sha256(self.e).hexdigest(),'config_sha256':'a'*64,'catalog_sha256':'b'*64}]};self.cfg={'sdk_port':9085,'intent_id':p.SDK5['intent'],'task_id':p.SDK5['task'],'launch_scope':{'intent_id':p.SDK5['intent'],'task_id':p.SDK5['task'],'generation':p.SDK5['generation'],'catalog_sha256':'c'*64}}
 def build(self,old=None,cfg=None,e=None):return m.build(m.canonical(old if old is not None else self.old),m.canonical(cfg if cfg is not None else self.cfg),self.e if e is None else e)
 def test_exact_additive_result(self):
  result=self.build();self.assertEqual(result['manifest']['entries'][:-1],self.old['entries']);self.assertEqual(result['manifest']['active_intent'],p.SDK5['intent']);self.assertEqual(result['transition_id'],m.TRANSITION_ID)
 def test_reused_path_wrong_scope_and_changed_evidence_refused(self):
  for case in ('path','active','port','generation','evidence','catalog'):
   old=copy.deepcopy(self.old);cfg=copy.deepcopy(self.cfg);e=self.e
   if case=='path':old['entries'][0]['evidence']=m.EVIDENCE
   if case=='active':old['active_intent']=p.SDK5['intent']
   if case=='port':cfg['sdk_port']=9084
   if case=='generation':cfg['launch_scope']['generation']='01ARZ3NDEKTSV4RRFFQ69G5FAM'
   if case=='evidence':e=b'changed'
   if case=='catalog':cfg['launch_scope']['catalog_sha256']='b'*64
   with self.subTest(case=case),self.assertRaises(ValueError):self.build(old,cfg,e)
if __name__=='__main__':unittest.main()
