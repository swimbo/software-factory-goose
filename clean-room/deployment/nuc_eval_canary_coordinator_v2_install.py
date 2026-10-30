"""Create-only fixed-path synthetic coordinator; never executes it."""
import hashlib,json,os,pathlib,stat
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGK';DEST=old.PREFIX/'evaluator';TARGET=DEST/'nuc_registry_eval_canary_coordinator_v2.py';SOURCE=pathlib.Path('/tmp/sfactory-evaluator-stage-20261030/nuc_registry_eval_canary_coordinator_v2.py');SHA='6f08f3540f9880fa63b28e9bef43eae7a0e6898d49a994b7f22aae0b2054af31'
START=old.ETC/'eval-canary-coordinator-v2-install-started.json';DONE=old.ETC/'eval-canary-coordinator-v2-install-complete.json';BROKER=pathlib.Path('/var/lib/software-factory-goose/evaluator')/G/'broker'
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def source():
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(1000,1000,1,0o600) and st.st_size<=65536,'source unavailable');data=os.read(fd,65537);require(len(data)==st.st_size and hashlib.sha256(data).hexdigest()==SHA,'source changed');return data
 finally:os.close(fd)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(x) for x in (TARGET,START,DONE)),'installation occupied');old.directory(DEST,0,2002,0o710);old.directory(SOURCE.parent,1000,1000,0o700);old.directory(BROKER,0,0,0o700);require(not os.listdir(BROKER),'challenge state occupied')
 provision=json.loads(old.read(old.ETC/'evaluator-canary-provision-complete.json',0o600));att=json.loads(old.read(old.ETC/'evaluator-canary-attestation-complete.json',0o600));cat=json.loads(old.read(old.ETC/'evaluator-canary-catalog.json',0o600,provision['catalog_sha256'],65536));require(cat['generation']==G and cat['purpose']=='synthetic-evaluator-canary-only' and att['generation']==G and att['fixture_only'] is True,'fixture unavailable')
 require(old.ctl('show','software-factory-goose-eval-canary.service','-p','MainPID','--value')==str(att['pid']) and old.ctl('show','software-factory-goose-eval-canary.service','-p','ActiveState','--value')=='active','broker unavailable')
 for e in cat['challenges']:
  cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+e['target'].lower()+'.slice');st=cg.stat();events=(cg/'cgroup.events').read_text().splitlines();require((st.st_dev,st.st_ino)==(e['cgroup_dev'],e['cgroup_ino']) and events.count('populated 0')==1 and events.count('frozen 0')==1,'challenge unavailable')
 source();return {'generation':G,'source_sha256':SHA,'attestation_sha256':att['manifest_sha256'],'catalog_sha256':provision['catalog_sha256'],'scope':'install fixed-path coordinator only; no execution'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600);data=source()
 fd=os.open(TARGET,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o440)
 try:
  v=memoryview(data)
  while v:
   n=os.write(fd,v);require(n>0,'short write');v=v[n:]
  os.fchmod(fd,0o440);os.fchown(fd,0,2002);os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(DEST);result={'generation':G,'source_sha256':SHA,'installed':True,'executed':False,'fixture_only':True};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
