import copy,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import nuc_root_grant_deadline as d
class GrantDeadlineTests(unittest.TestCase):
 def fixture(self):
  g='01M65N5TM28WPH7BKQ153SPNJR';boot='boot';scope={'task_id':'task','intent_id':'intent','queue_id':'queue','generation':g,'spec':{'repository':'repo','base_revision':'b'*40},'worker_id':'worker','catalog_sha256':'a'*64}
  recipe={'schema':1,'purpose':'nuc-goose-write-files-v1','generation':g,'task_id':'task','worker_uid':2001,'goose_binary_sha256':d.GOOSE,'worker_image_id':'sha256:509d7c54cfdbf6afd9e1c80ff924d367bdaf0979e6ef63b1f7d1134ce3a9710a','worker_program_sha256':'c0f51ee7767c6448c1fa3908e137c280753de302af9e7196751bb67fbc601df1','writer_image_id':'sha256:2efe778192492f6934540be9771bc1057b4724fe20bed6f71a362a4b91636b48','writer_program_sha256':'4ade60e556a391795b8f2b13a5e6d52efb68a04d6d806f5e0bf76e3cdc0d3d8c','profile_sha256':'5'*64,'prompt_sha256':'6'*64,'relay_scope_template_sha256':'7'*64,'provider_binding_sha256':'8'*64,'fixed_parent':'sfactory'+g.lower()+'.slice'}
  c={'schema':1,'scope':scope,'boot_id':boot,'cgroup_dev':29,'cgroup_ino':42,'recipe_sha256':d.digest(d.canonical(recipe)),'max_expiry_ms':300}
  grant={'scope':scope,'generation':g,'attempt':1,'token_sha256':'c'*64,'expires_at_ms':200,'hard_deadline_ms':300};gb=d.canonical(grant);cb=d.canonical(c);binding=d.digest(b'sfactory-root-grant-v1\0'+len(gb).to_bytes(8,'big')+gb+len(cb).to_bytes(8,'big')+cb)
  verified={'schema':1,'generation':g,'binding_sha256':binding,'reservation':grant};stop={'target_id':g,'generation':g,'boot_id':boot,'cgroup_dev':29,'cgroup_ino':42}
  return c,recipe,verified,stop,boot,g
 def test_exact_binding_positive(self):
  c,r,v,s,b,g=self.fixture();self.assertEqual(d.matches(c,r,v,s,b,g,100),(v['binding_sha256'],200))
 def test_changed_recipe_scope_boot_or_expiry_denied(self):
  c,r,v,s,b,g=self.fixture()
  for kind in ('recipe','scope','boot','expiry','binding','cgroup'):
   cc,rr,vv,ss=copy.deepcopy((c,r,v,s))
   if kind=='recipe':rr['worker_uid']=0
   if kind=='scope':vv['reservation']['scope']['worker_id']='wrong'
   if kind=='boot':ss['boot_id']='wrong'
   if kind=='expiry':vv['reservation']['expires_at_ms']=100
   if kind=='binding':vv['binding_sha256']='0'*64
   if kind=='cgroup':ss['cgroup_ino']=43
   with self.subTest(kind=kind),self.assertRaises(RuntimeError):d.matches(cc,rr,vv,ss,b,g,100)
 def test_ambiguous_timer_start_retains_intent(self):
  _,_,_,_,boot,g=self.fixture()
  spec={'target':g,'boot_id':boot,'catalog_sha256':'1'*64,'recipe_sha256':'2'*64,'stop_catalog_sha256':'3'*64,'verified_grant_sha256':'4'*64,'binding_sha256':'5'*64,'expiry_ms':time.time_ns()//1_000_000+30_000,'duration_seconds':10,'timer':'unit.timer','service':'unit.service','purpose':'grant-bound-production-not-activated'}
  class Deadline:
   BINARY='/fixed/root/binary'
   @staticmethod
   def store(path,obj):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(obj,f);f.flush();os.fsync(f.fileno())
   @staticmethod
   def run(*args):raise TimeoutError('manager reply lost')
  with tempfile.TemporaryDirectory() as t,patch.object(d,'STATE',Path(t)),patch.object(d,'plan',return_value=spec):
   with self.assertRaises(TimeoutError):d.arm(Deadline,spec)
   self.assertTrue((Path(t)/(g+'.deadline-intent.json')).exists())
   self.assertFalse((Path(t)/(g+'.deadline-armed.json')).exists())
if __name__=='__main__':unittest.main()
