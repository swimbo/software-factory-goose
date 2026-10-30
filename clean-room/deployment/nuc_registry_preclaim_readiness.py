"""Read-only registry preclaim check; run natively with no Linux capabilities."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old

HELPER=old.PREFIX/'root-launch-host.py'; HELPER_SHA='604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e'
PROBE=old.PREFIX/'registry-attestor-probe'; PROBE_SHA='aa2868160da22acbdae103c118f952cc8d8675fe31b0558dec969c7f96b21642'
NATIVE=old.PREFIX/'native-registry-readiness-cap0'; NATIVE_SHA='932d93b82b2dfdeca4d83bb2f1033d5e9ffdd34c3f6f7619c37ed8bad77e607b'
ROOT=old.ETC;STATE=pathlib.Path('/var/lib/software-factory-goose/stop')

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def run_json(path,expected_sha):
 old.read(path,0o755,expected_sha,10_000_000)
 p=subprocess.run([str(path)],env=old.ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=50,check=False)
 require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'native probe failed')
 return json.loads(p.stdout)
def check_no_effects(g):
 names={p.name for p in STATE.iterdir() if p.name.startswith(g+'.')};lock=g+'.callback-lifecycle.lock'
 require(names=={lock},'generation already has effects or lifecycle lock missing')
 require(old.read(STATE/lock,0o600,maxsize=0)==b'','lifecycle lock contents unexpected')
def plan():
 require(os.geteuid()==0 and os.getegid()==0,'root required')
 # The native binary itself rejects any other effective/permitted/bounding/ambient
 # capability set and NNP=0, and uses the real protected Rust registry loader.
 active=run_json(NATIVE,NATIVE_SHA)
 require(set(active)=={'intent_id','task_id','generation','catalog_sha256','registry_validated','capabilities_empty','grant_requested'} and active['registry_validated'] is True and active['capabilities_empty'] is True and active['grant_requested'] is False,'registry identity unavailable')
 g=active['generation'];task=active['task_id']
 require(isinstance(g,str) and len(g)==26 and all(c in '0123456789ABCDEFGHJKMNPQRSTVWXYZ' for c in g),'invalid generation')
 require(run_json(PROBE,PROBE_SHA)=={'service_attested':True,'grant_requested':False},'registry service not attested')
 raw=old.read(HELPER,0o755,HELPER_SHA,1_000_000);scope={'__name__':'preclaim_readonly'};exec(compile(raw,'<pinned-root-helper>','exec'),scope)
 cat=scope['load'](ROOT/'launch-catalog'/(g+'.json'));recipe=scope['load'](ROOT/'launch-catalog'/(g+'.recipe.json'));stop=scope['load'](ROOT/'tasks'/(g+'.json'))
 require(cat['scope']['generation']==g and cat['scope']['task_id']==task and cat['scope']['catalog_sha256']==active['catalog_sha256'] and stop['generation']==g and stop['task_id']==task and scope['digest'](scope['canonical'](recipe))==cat['recipe_sha256'],'catalog mismatch')
 check_no_effects(g)
 with scope['callback_lifecycle'](g):
  check_no_effects(g)
  scope['callback_rebind_allowed'](g)
  scope['modules']();scope['provenance'](recipe);scope['engine_guard']();scope['validate_inputs'](g,recipe);names=scope['validate_units'](g);template=scope['scope_template'](g,cat,recipe,'0'*64)
  for role,image,program in (('worker',scope['WORKER'],'nuc_goose_worker.py'),('writer',scope['WRITER'],'nuc_fixed_writer.py')):
   images=json.loads(scope['fixed_run'](scope['DOCKER']+['image','inspect',image]))
   require(len(images)==1 and images[0]['Id']==image and images[0]['Config'].get('Entrypoint')==['/usr/local/bin/python3','-I','-B','/factory/'+program] and images[0]['Config'].get('Cmd') in (None,[]),'pinned '+role+' image unavailable')
  existing=scope['fixed_run'](scope['DOCKER']+['ps','-a','--filter','label=org.software-factory.generation='+g,'--format','{{.ID}}'])
  require(not existing.strip(),'generation container already exists')
  cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+g.lower()+'.slice');st=os.stat(cg)
  events=(cg/'cgroup.events').read_text().splitlines()
  require((st.st_dev,st.st_ino)==(cat['cgroup_dev'],cat['cgroup_ino'])==(stop['cgroup_dev'],stop['cgroup_ino']) and events.count('populated 0')==1 and events.count('frozen 0')==1,'generation cgroup not empty and unfrozen')
  require(template['grant_sha256']=='0'*64 and template['generation']==g and template['task_id']==task,'template mismatch')
  check_no_effects(g)
  scope['callback_rebind_allowed'](g)
  require(run_json(PROBE,PROBE_SHA)=={'service_attested':True,'grant_requested':False},'registry service changed')
  require(run_json(NATIVE,NATIVE_SHA)==active,'registry changed')
 return {'component':'registry-preclaim-readiness','generation':g,'task':task,'catalog_sha256':active['catalog_sha256'],'recipe_sha256':cat['recipe_sha256'],'units':names,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'attestor_passed':True,'claim_requested':False,'container_started':False,'provider_called':False}
