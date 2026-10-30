"""Read-only verification of the installed root launch helper before claim."""
import hashlib,json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
G='01M65NEH5T767H8Q5X71TTFR5S';TASK='01M65NEH5TBPKNDW21TE6FR3XA'
HELPER=old.PREFIX/'root-launch-host.py';HELPER_SHA='3de11eef342e32c98c2d87659d647fc33547048b7ea80699e3bf117ec5d9a06d'
PROBE=old.PREFIX/'root-attestor-probe';PROBE_SHA='09a8bc07db0b5573cd4cce738dc41d593b01acdf5c4b328fd40a836896e7f8f6'
STATE=pathlib.Path('/var/lib/software-factory-goose/stop');ROOT=old.ETC
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def make_plan(host):
 require(os.geteuid()==0,'root required')
 raw=old.read(HELPER,0o755,HELPER_SHA,1_000_000);old.read(PROBE,0o700,PROBE_SHA,10_000_000)
 p=subprocess.run([str(PROBE)],env=old.ENV,capture_output=True,timeout=50,check=False);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192 and json.loads(p.stdout)=={'service_attested':True,'grant_requested':False},'service attestation unavailable')
 scope={'__name__':'preclaim_readonly'};exec(compile(raw,'<pinned-root-helper>','exec'),scope)
 cat=scope['load'](ROOT/'launch-catalog'/(G+'.json'));recipe=scope['load'](ROOT/'launch-catalog'/(G+'.recipe.json'));stop=scope['load'](ROOT/'tasks'/(G+'.json'))
 require(cat['scope']['generation']==G and cat['scope']['task_id']==TASK and stop['generation']==G and stop['task_id']==TASK and scope['digest'](scope['canonical'](recipe))==cat['recipe_sha256'],'preclaim catalog mismatch')
 require(not any(p.name.startswith(G+'.') for p in STATE.iterdir()),'generation already has effects')
 scope['modules']();scope['provenance'](recipe);scope['engine_guard']();paths,dirs=scope['validate_inputs'](G,recipe);names=scope['validate_units'](G);template=scope['scope_template'](G,cat,recipe,'0'*64)
 # Image and container inventory are read-only; no Docker create/start occurs.
 for role,image,program in (('worker',scope['WORKER'],'nuc_goose_worker.py'),('writer',scope['WRITER'],'nuc_fixed_writer.py')):
  images=json.loads(scope['fixed_run'](scope['DOCKER']+['image','inspect',image]))
  require(len(images)==1 and images[0]['Id']==image and images[0]['Config'].get('Entrypoint')==['/usr/local/bin/python3','-I','-B','/factory/'+program] and images[0]['Config'].get('Cmd') in (None,[]),'pinned '+role+' image unavailable')
 existing=scope['fixed_run'](scope['DOCKER']+['ps','-a','--filter','label=org.software-factory.generation='+G,'--format','{{.ID}}'])
 require(not existing.strip(),'generation container already exists')
 cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+G.lower()+'.slice');st=os.stat(cg)
 require((st.st_dev,st.st_ino)==(cat['cgroup_dev'],cat['cgroup_ino'])==(stop['cgroup_dev'],stop['cgroup_ino']) and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'generation cgroup not empty')
 require(template['grant_sha256']=='0'*64 and template['generation']==G and template['task_id']==TASK,'template mismatch')
 require(not any(p.name.startswith(G+'.') for p in STATE.iterdir()),'generation changed during readiness')
 return {'component':'real-preclaim-readiness','source_sha256':host.source_digest,'generation':G,'task':TASK,'catalog_sha256':scope['digest'](scope['rootfile'](ROOT/'launch-catalog'/(G+'.json'))),'recipe_sha256':cat['recipe_sha256'],'helper_sha256':HELPER_SHA,'units':names,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'attestor_passed':True,'claim_requested':False,'container_started':False,'provider_called':False}
