"""Create-only registry sidecar proposal; no service start, registration or claim."""
import hashlib,json,os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_real_sidecar_install as real
import nuc_real_sidecar_activate as active
INTENT='01M65RMR3F959RPSERJ681DQ43';TASK='01M65RMR3FE6FQTFRBHERRHXRG';GEN='01M65RMR3F04YB1B016EBBSXGG'
QUEUE='hello-int-loop-20261030-r2';WORKER='hello-int-loop-worker-r2';NAME='software-factory-goose-registry-'
BIN=old.PREFIX/'private-registry-sidecar';SOURCE=pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX/stripped/private-registry-sidecar')
SOURCE_SHA='9e17154941cc9d7c2a8d508dddc617249172bf1f13fc6d7758a9b1161d5029ec'
CFG=old.ETC/'registry-next-runtime.json';EVIDENCE=old.ETC/'registry-next-evidence.json';MANIFEST=old.ETC/'catalog-registry.json';MARKER=old.ETC/'registry-bootstrap-complete'
REGISTER=old.PREFIX/'private-registry-register.py';START=old.ETC/'registry-sidecar-started.json';DONE=old.ETC/'registry-sidecar-complete.json'
REGISTER_SOURCE=real.REGISTER_SOURCE.replace(b'9083',b'9084').replace(b'REAL_REGISTRATION ',b'REGISTRY_REGISTRATION ')

def packed(x):return json.dumps(x,ensure_ascii=False,separators=(',',':')).encode()
def canonical(x):return json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def generated():
 # Revalidate the fresh owned repository and its committed contract via the real installer.
 real.generated();previous=json.loads(old.read(real.CONFIG,0o644,'1fe972454f55de3f6dd9e3f7783e810470e628a7f9da304a740412062a9dc1bf'))
 evidence=old.read(real.EVIDENCE,0o644,'b67520e3e8ab7f5e700f7e77db5493c1dcd2a6e0ab489c130bed44b6f3f247b2')
 cfg=dict(previous);cfg.update(sdk_port=9084,worker_id=WORKER,queue_id=QUEUE,intent_id=INTENT,task_id=TASK)
 req=cfg['request'];facts=cfg['facts'];request={k:req[k] for k in ('schema_version','repository','target_ref','base_revision','intent','acceptance_criteria')};features={k:facts[k] for k in ('spec_clarity','blast_radius','novelty','reversibility','has_codified_knowledge','fatal')}
 fingerprint=sha(packed([cfg['principal'],QUEUE,INTENT,TASK,request,features,cfg['evidence_sha256']]))
 cfg['launch_scope']={'task_id':TASK,'intent_id':INTENT,'queue_id':QUEUE,'generation':GEN,'spec':{'repository':req['repository'],'base_revision':req['base_revision']},'worker_id':WORKER,'catalog_sha256':fingerprint}
 config=canonical(cfg)+b'\n'
 entries=[]
 for c,e,cs,es,fp in [
  ('runtime.json','evidence.json','53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6','b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a','e6e11a0b060dc2760f4c44ba607c45a931c01b839039158cbbec1e5f7e9ebbaf'),
  ('grant-runtime.json','grant-evidence.json','70c14a65b8229304e04eb7e693eb7dc2ef20c7c947349e2e09e0b08dae84547f','b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a','4218228a2a9c0fcc51ec838414ebd92542b18e06ddd40d7a1a2b628d4d8caf19'),
  ('real-runtime.json','real-evidence.json','1fe972454f55de3f6dd9e3f7783e810470e628a7f9da304a740412062a9dc1bf','b67520e3e8ab7f5e700f7e77db5493c1dcd2a6e0ab489c130bed44b6f3f247b2','cc5c4ae8ec34730f037fddefcb7b6d92fd4eab2bc1ac06dabd92abd747c1f1b7')]:
  old.read(old.ETC/c,0o644,cs);old.read(old.ETC/e,0o644,es);entries.append({'config':c,'evidence':e,'config_sha256':cs,'evidence_sha256':es,'catalog_sha256':fp})
 entries.append({'config':CFG.name,'evidence':EVIDENCE.name,'config_sha256':sha(config),'evidence_sha256':sha(evidence),'catalog_sha256':fingerprint})
 return cfg,config,evidence,canonical({'schema':1,'active_intent':INTENT,'entries':entries})+b'\n'

def units():
 out={}
 for name,data in real.units().items():
  n=name.replace(real.NAME,NAME)
  text=data.decode().replace(real.NAME,NAME).replace('real-intake.sock','registry-intake.sock').replace('real-worker.sock','registry-worker.sock').replace('real-launch-grant.sock','registry-launch-grant.sock').replace('private-real-sidecar','private-registry-sidecar').replace('private-real-register.py','private-registry-register.py')
  out[n]=text.encode()
 return out

def source_info():
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_nlink,stat.S_IMODE(s.st_mode))==(1000,1,0o700) and s.st_size<100_000_000,'binary source mismatch');h=hashlib.sha256();total=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   total+=len(b);h.update(b)
  require(total==s.st_size and h.hexdigest()==SOURCE_SHA,'binary source changed');return {'dev':s.st_dev,'ino':s.st_ino,'size':total,'sha256':SOURCE_SHA}
 finally:os.close(fd)

def plan():
 require(os.geteuid()==0,'root required')
 for path,uid,gid,mode in [(old.ETC,0,0,0o711),(old.RUN,0,0,0o755),(old.UNIT,0,0,0o755),(old.PREFIX,0,0,0o755),(SOURCE.parent,1000,1000,0o700)]:old.directory(path,uid,gid,mode)
 dest=[START,DONE,MARKER,CFG,EVIDENCE,MANIFEST,BIN,REGISTER]+[old.UNIT/n for n in units()]+[old.RUN/n for n in ('registry-intake.sock','registry-worker.sock','registry-launch-grant.sock')]
 require(not any(os.path.lexists(p) for p in dest),'registry destination occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in units():
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','unit name occupied')
  for parent in map(pathlib.Path,paths):
   for p in (parent/name,parent/(name+'.d'),parent/'service.d',parent/'socket.d'):require(not os.path.lexists(p),'unit alias/drop-in collision')
 cfg,data,evidence,manifest=generated();return {'intent':INTENT,'task':TASK,'generation':GEN,'catalog_sha256':cfg['launch_scope']['catalog_sha256'],'config_sha256':sha(data),'evidence_sha256':sha(evidence),'registry_sha256':sha(manifest),'source':source_info(),'units':{n:sha(v) for n,v in units().items()},'register_sha256':sha(REGISTER_SOURCE),'old':old.old_snapshot(),'prior_sidecar':old.sidecar_running(),'real_sidecar':active.service_running(),'scope':'create-only registry, no registration or claim'}

def verify_loaded():
 for name in units():
  props=dict(line.split('=',1) for line in old.ctl('show',name,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec','--no-pager').splitlines())
  require(props.get('LoadState')=='loaded' and props.get('ActiveState')=='inactive' and props.get('Names')==name and props.get('FragmentPath')==str(old.UNIT/name) and props.get('DropInPaths','')=='','unit identity mismatch')
  if name.endswith('.service'):require(props.get('MainPID')=='0' and props.get('MemoryMax')==str(512*1024**2) and props.get('TasksMax')=='128' and props.get('CPUQuotaPerSecUSec') in ('1s','1000000us'),'unit limits mismatch')

def apply(approved):
 require(plan()==approved,'registry plan changed');old.store(START,canonical(approved)+b'\n',0o600)
 cfg,data,evidence,manifest=generated();require((sha(data),sha(evidence),sha(manifest))==(approved['config_sha256'],approved['evidence_sha256'],approved['registry_sha256']),'catalog changed')
 old.store(CFG,data);old.store(EVIDENCE,evidence);old.store(MANIFEST,manifest)
 src=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);dst=os.open(BIN,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o755)
 try:
  h=hashlib.sha256();total=0
  while True:
   block=os.read(src,65536)
   if not block:break
   h.update(block);total+=len(block);view=memoryview(block)
   while view:
    n=os.write(dst,view);require(n>0,'short binary write');view=view[n:]
  require(total==approved['source']['size'] and h.hexdigest()==SOURCE_SHA,'binary changed');os.fchmod(dst,0o755);os.fsync(dst)
 finally:os.close(src);os.close(dst)
 old.syncdir(old.PREFIX);old.store(REGISTER,REGISTER_SOURCE,0o755)
 for name,content in units().items():old.store(old.UNIT/name,content,0o644)
 old.ctl('daemon-reload');verify_loaded()
 require(old.old_snapshot()==approved['old'] and old.sidecar_running()==approved['prior_sidecar'] and active.service_running()==approved['real_sidecar'],'preserved runtime changed')
 result={'installed':True,'registered':False,'started':False,'claim_requested':False,'catalog_sha256':cfg['launch_scope']['catalog_sha256'],'registry_sha256':sha(manifest)};old.store(DONE,canonical(result)+b'\n',0o600);return result
