"""Quiescent create-only, versioned evaluator backend upgrade; no activation."""
import hashlib,json,os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGK';DEST=old.PREFIX/'evaluator';TARGET=DEST/'nuc_registry_eval_canary_runtime.py';SOURCE=pathlib.Path('/tmp/sfactory-evaluator-stage-20261030/nuc_registry_eval_canary_runtime_v2.py')
NEW='217d03d78d642db1aa0162c934aadd573905c7c7784328ada308f7e9585ac48d';ROOT=old.ETC;STATE=pathlib.Path('/var/lib/software-factory-goose/evaluator')/G
START=ROOT/'evaluator-canary-runtime-v2-started.json';DONE=ROOT/'evaluator-canary-runtime-v2-complete.json';BACKUP=ROOT/'evaluator-canary-runtime-v1.backup';TEMP=DEST/'.runtime-v2.pending'
def require(x,msg):
 if not x:raise RuntimeError(msg)
def group_read(path,uid,gid,mode,digest):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(uid,gid,1,mode) and st.st_size<=1000000,'source unavailable');data=os.read(fd,1000001);require(len(data)==st.st_size and hashlib.sha256(data).hexdigest()==digest,'source changed');return data,{'dev':st.st_dev,'ino':st.st_ino,'sha256':digest}
 finally:os.close(fd)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,BACKUP,TEMP)),'upgrade already attempted');old.directory(DEST,0,2002,0o710);old.directory(STATE/'broker',0,0,0o700);require(not os.listdir(STATE/'broker'),'challenge state exists')
 provision=json.loads(old.read(ROOT/'evaluator-canary-provision-started.json',0o600));receipt=json.loads(old.read(ROOT/'evaluator-canary-provision-complete.json',0o600));cat=json.loads(old.read(ROOT/'evaluator-canary-catalog.json',0o600,receipt['catalog_sha256'],65536));require(receipt.get('fixture_only') is True and cat.get('generation')==G and cat.get('purpose')=='synthetic-evaluator-canary-only' and len(cat.get('challenges',[]))==22,'fixture unavailable')
 helper_raw=old.read(old.PREFIX/'root-launch-host.py',0o755,'604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e',1000000);helper={'__name__':'eval_upgrade_helper'};exec(compile(helper_raw,'<pinned-helper>','exec'),helper);helper['engine_guard']()
 previous=provision['source_sha256']['nuc_registry_eval_canary_runtime.py'];_,oldinfo=group_read(TARGET,0,2002,0o440,previous);_,newinfo=group_read(SOURCE,1000,1000,0o600,NEW)
 for unit in ('software-factory-goose-eval-canary.service','software-factory-goose-eval-canary.socket'):
  require(old.ctl('show',unit,'-p','ActiveState','--value')=='inactive' and old.ctl('show',unit,'-p','Job','--value')=='','fixture service active')
 targets=[]
 for item in cat['challenges']:
  target=item['target'];require(isinstance(target,str) and re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',target) and target not in targets,'target mismatch');targets.append(target)
  cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+target.lower()+'.slice');st=os.stat(cg);events=(cg/'cgroup.events').read_text().splitlines();require((st.st_dev,st.st_ino)==(item['cgroup_dev'],item['cgroup_ino']) and events.count('populated 0')==1 and events.count('frozen 0')==1,'fixture cgroup occupied')
  for suffix in ('closed','eval-deadline-intent.json','eval-deadline-armed.json'):require(not os.path.lexists(pathlib.Path('/var/lib/software-factory-goose/stop')/(target+'.'+suffix)),'challenge attempted')
  for suffix in ('.timer','.service'):require(old.ctl('show','sfactorydeadline'+target.lower()+suffix,'-p','LoadState','--value')=='not-found','deadline exists')
  p=subprocess.run(['/usr/bin/docker','--host','unix:///run/docker.sock','--config','/run/software-factory-goose/docker-empty-config','ps','-a','--filter','label=org.software-factory.evaluation='+target,'--format','{{.ID}}'],env=old.ENV,capture_output=True,timeout=10,check=True);require(not p.stdout.strip() and len(p.stderr)<8192,'fixture container exists')
 helper['engine_guard']()
 return {'generation':G,'catalog_sha256':receipt['catalog_sha256'],'old':oldinfo,'new':newinfo,'targets':targets,'scope':'replace pinned evaluator fixture runtime only; no activation'}
def apply(approved):
 require(plan()==approved,'upgrade plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 original,_=group_read(TARGET,0,2002,0o440,approved['old']['sha256']);old.store(BACKUP,original,0o600);data,_=group_read(SOURCE,1000,1000,0o600,NEW)
 fd=os.open(TEMP,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o440)
 try:
  view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fchmod(fd,0o440);os.fchown(fd,0,2002);os.fsync(fd)
 finally:os.close(fd)
 _,current=group_read(TARGET,0,2002,0o440,approved['old']['sha256']);require(current==approved['old'],'old identity changed');os.replace(TEMP,TARGET);old.syncdir(DEST);group_read(TARGET,0,2002,0o440,NEW)
 result={'generation':G,'runtime_sha256':NEW,'previous_sha256':approved['old']['sha256'],'fixture_only':True,'activated':False};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
