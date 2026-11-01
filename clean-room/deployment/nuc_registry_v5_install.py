"""Create-only SDK5 files and render a proposed catalog; never register or start."""
import hashlib,json,os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_sidecar_install as prior
import nuc_registry_sidecar_activate as prior_active
INTENT='01M66XF6HPWC3NXMAFDHKHDSP7';TASK='01M66XF6HPKEC38CJJP78KQJVC';GEN='01M66XF6HPBETAJ5V0G45TM8NQ'
QUEUE='hello-int-loop-20261030-r3';WORKER='hello-int-loop-worker-r3'
NAME='software-factory-goose-registry-v5-'
SOURCE=pathlib.Path('/tmp/sfactory-registry-v5-candidate-20261030/private-registry-v5-sidecar-v2')
SOURCE_SHA='c26888e7091734e2f7692251f8c986e0b836936f397e74e74f3f2da1b7e69267'
BIN=old.PREFIX/'private-registry-v5-sidecar';REGISTER=old.PREFIX/'private-registry-v5-register.py'
START=old.ETC/'registry-v5-install-started.json';DONE=old.ETC/'registry-v5-install-complete.json'
MARKER=old.ETC/'registry-v5-bootstrap-complete'
REGISTER_SOURCE=prior.REGISTER_SOURCE.replace(b'9084',b'9085').replace(b'REGISTRY_REGISTRATION ',b'REGISTRY_V5_REGISTRATION ')
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def canonical(x):return json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def units():
 result={}
 for name,data in prior.units().items():
  n=name.replace(prior.NAME,NAME)
  v=data.decode().replace(prior.NAME,NAME).replace('registry-intake.sock','registry-v5-intake.sock').replace('registry-worker.sock','registry-v5-worker.sock').replace('registry-launch-grant.sock','registry-v5-launch-grant.sock').replace('private-registry-sidecar','private-registry-v5-sidecar').replace('private-registry-register.py','private-registry-v5-register.py')
  result[n]=v.encode()
 return result
def proposed_config():
 cfg=json.loads(old.read(prior.CFG,0o644,'d413213318a6555c62fc24ffa848c1dda42db510d92a1160c6f86f20a803b23b'))
 cfg.update(sdk_port=9085,worker_id=WORKER,queue_id=QUEUE,intent_id=INTENT,task_id=TASK)
 req=cfg['request'];facts=cfg['facts'];request={k:req[k] for k in ('schema_version','repository','target_ref','base_revision','intent','acceptance_criteria')};features={k:facts[k] for k in ('spec_clarity','blast_radius','novelty','reversibility','has_codified_knowledge','fatal')}
 fp=sha(prior.packed([cfg['principal'],QUEUE,INTENT,TASK,request,features,cfg['evidence_sha256']]))
 cfg['launch_scope']={'task_id':TASK,'intent_id':INTENT,'queue_id':QUEUE,'generation':GEN,'spec':{'repository':req['repository'],'base_revision':req['base_revision']},'worker_id':WORKER,'catalog_sha256':fp}
 data=canonical(cfg)+b'\n';return cfg,data,fp
def source_info():
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(1000,1000,1,0o700) and 0<s.st_size<100_000_000,'candidate identity mismatch')
  h=hashlib.sha256();total=0
  while b:=os.read(fd,65536):h.update(b);total+=len(b);require(total<=s.st_size,'candidate grew')
  require(total==s.st_size and h.hexdigest()==SOURCE_SHA,'candidate digest mismatch')
  return {'dev':s.st_dev,'ino':s.st_ino,'size':total,'sha256':SOURCE_SHA}
 finally:os.close(fd)
def plan():
 require(os.geteuid()==0,'root required')
 for p,u,g,m in [(old.ETC,0,0,0o711),(old.RUN,0,0,0o755),(old.UNIT,0,0,0o755),(old.PREFIX,0,0,0o755),(SOURCE.parent,1000,1000,0o700)]:old.directory(p,u,g,m)
 dest=[START,DONE,MARKER,BIN,REGISTER]+[old.UNIT/n for n in units()]+[old.RUN/n for n in ('registry-v5-intake.sock','registry-v5-worker.sock','registry-v5-launch-grant.sock')]
 require(not any(os.path.lexists(p) for p in dest),'destination occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in units():
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','unit occupied')
  for parent in map(pathlib.Path,paths):
   for p in (parent/name,parent/(name+'.d'),parent/'service.d',parent/'socket.d',parent/'software-factory-goose-.service.d',parent/'software-factory-goose-registry-.service.d',parent/'software-factory-goose-registry-v5-.service.d'):require(not os.path.lexists(p),'unit collision')
 cfg,data,fp=proposed_config()
 return {'source':source_info(),'units':{n:sha(v) for n,v in units().items()},'register_sha256':sha(REGISTER_SOURCE),'proposed_config':cfg,'proposed_config_sha256':sha(data),'catalog_sha256':fp,'prior_sdk4':prior_active.service_running(),'old':old.old_snapshot(),'scope':'create-only SDK5 files; no catalog mutation, activation or registration'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,canonical(approved)+b'\n',0o600)
 src=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);dst=os.open(BIN,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  h=hashlib.sha256();total=0
  while b:=os.read(src,65536):
   total+=len(b);require(total<=approved['source']['size'],'candidate grew');h.update(b);v=memoryview(b)
   while v:
    n=os.write(dst,v);require(n>0,'short write');v=v[n:]
  require(total==approved['source']['size'] and h.hexdigest()==SOURCE_SHA,'candidate changed');os.fchmod(dst,0o755);os.fsync(dst)
 finally:os.close(src);os.close(dst)
 old.syncdir(old.PREFIX);old.store(REGISTER,REGISTER_SOURCE,0o755)
 for name,data in units().items():old.store(old.UNIT/name,data,0o644)
 old.ctl('daemon-reload')
 for name in units():
  p=dict(line.split('=',1) for line in old.ctl('show',name,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec','--no-pager').splitlines())
  require(p.get('LoadState')=='loaded' and p.get('ActiveState')=='inactive' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='','unit identity mismatch')
  if name.endswith('.service'):require(p.get('MainPID')=='0' and p.get('MemoryMax')==str(512*1024**2) and p.get('TasksMax')=='128' and p.get('CPUQuotaPerSecUSec') in ('1s','1000000us'),'resource mismatch')
 require(prior_active.service_running()==approved['prior_sdk4'] and old.old_snapshot()==approved['old'],'existing runtime changed')
 result={'installed':True,'started':False,'registered':False,'catalog_mutated':False,'candidate_sha256':SOURCE_SHA};old.store(DONE,canonical(result)+b'\n',0o600);return result
