import copy,unittest
import nuc_registry_v5_pass_evidence as p
class PassEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.files={'hello.py':b'hello','test_hello.py':b'test'};self.hashes={k:p.sha(v) for k,v in self.files.items()};self.scope={'generation':p.G,'task_id':p.TASK,'binding_sha256':'a'*64,'boot_id':'boot','cgroup_dev':1,'cgroup_ino':2}
  self.execution={'schema':1,'generation':p.G,'binding_sha256':'a'*64,'writer_id':'b'*64,'goose_id':'c'*64,'candidate_sha256':self.hashes,'kernel_closed_frozen_empty':True,'exact_ids_removed':True,'slice_retained_frozen':True,'engine_reconciled_for_exact_ids':True}
  self.evaluation={'schema':1,'generation':p.G,'candidate_sha256':self.hashes,'scenario_votes':[3]*7,'repetitions':3,'candidate_tests':'pass','challenges':22}
  self.challenges=[]
  for i in range(1,23):
   target=f'{i:026d}';ident=f'{i:064x}';done={'schema':1,'generation':p.G,'sequence':i,'intent_sha256':'d'*64,'candidate_sha256':self.hashes,'container_id':ident,'stdout_sha256':'f'*64,'stderr_sha256':'e'*64,'exit_code':0};removed={'target':target,'id':ident,'frozen_empty':True};observation={'target_id':target,'boot_id':'boot','cgroup_dev':1,'cgroup_ino':2,'observed':True,'closed':True,'frozen':True,'empty':True,'engine_reconciled':False};self.challenges.append({'target':target,'cgroup_dev':1,'cgroup_ino':2,'done':done,'removed':removed,'observation':observation})
  self.git={'schema':1,'generation':p.G,'revision':'e'*40,'files':self.hashes,'baseline_ancestor':True,'clean_exact_tree':True}
 def run_check(self):return p.validate(self.scope,self.execution,self.evaluation,self.challenges,self.git,self.files)
 def test_accepts_exact_independent_evidence(self):
  result=self.run_check();self.assertEqual(result['spend'],'unknown');self.assertFalse(result['promotion'])
 def test_cross_generation_and_reused_challenge_fail(self):
  self.challenges[0]['done']['generation']='0'*26
  with self.assertRaises(ValueError):self.run_check()
  self.challenges[0]['done']['generation']=p.G;self.challenges[1]['target']=self.challenges[0]['target']
  with self.assertRaises(ValueError):self.run_check()
 def test_incomplete_cleanup_and_forged_git_fail(self):
  self.execution['exact_ids_removed']=False
  with self.assertRaises(ValueError):self.run_check()
  self.execution['exact_ids_removed']=True;self.git['files']=dict(self.hashes,**{'hello.py':'f'*64})
  with self.assertRaises(ValueError):self.run_check()
 def test_forged_evaluation_or_extra_fields_fail(self):
  self.evaluation['scenario_votes']=[2]*7
  with self.assertRaises(ValueError):self.run_check()
  self.evaluation['scenario_votes']=[3]*7;self.challenges[0]['extra']=True
  with self.assertRaises(ValueError):self.run_check()
if __name__=='__main__':unittest.main()
