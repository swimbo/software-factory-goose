"""Install the guarded SDK5 binary while inactive; preserve its prior bytes.

No socket, service, registration, claim or authorization is started here.
Uncertain effects retain the immutable intent and exact backup/staged files.
"""
import hashlib,json,os,pathlib,stat
import nuc_grant_sidecar_install as old
import nuc_registry_v5_install as legacy
NAME=legacy.NAME;BIN=legacy.BIN;GEN=legacy.GEN;INTENT=legacy.INTENT;TASK=legacy.TASK
units=legacy.units
STAGE=pathlib.Path('/tmp/sfactory-sdk5-guarded-stage-q0q7wl8a')
SOURCE=STAGE/'private-registry-v5-sidecar'
SOURCE_SHA='20c91c027d5a8cf4d430e59aa5afeb365df7c54177ce0ebb5f54f86f5f416349'
PRIOR_SHA='c26888e7091734e2f7692251f8c986e0b836936f397e74e74f3f2da1b7e69267'
GUARD_SHA='986a8b7e0e86493245fda320db979779056c1cc209ee49a539bebead8029f2c3'
ENTRY_SHA='9446aa194b14406715b5c4787cf9a8c6550864715c1eb2bd21145c913d914766'
COMMIT='6e0537c686264a8f4f661862ddac710960a0400d'
CANARY_BIN_SHA='e6c12ae30c1903566f05e46b9baa064ac65bd9e7e873bd78204e5ab66d256beb'
CANARY=old.ETC/'sdk5-fdguard-canary-recovery-complete.json'
BACKUP=old.PREFIX/'private-registry-v5-sidecar.pre-guard'
TEMP=old.PREFIX/'private-registry-v5-sidecar.guarded-new'
START=old.ETC/'registry-v5-guarded-runtime-started.json';DONE=old.ETC/'registry-v5-guarded-runtime-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
def identity(path,uid,mode,pin):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(uid,uid,1,mode) and 0<s.st_size<=100000000,'binary metadata unavailable')
  h=hashlib.sha256();total=0
  while b:=os.read(fd,65536):total+=len(b);require(total<=s.st_size,'binary grew');h.update(b)
  after=os.fstat(fd);require((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and total==s.st_size and h.hexdigest()==pin,'binary changed')
  return {'dev':s.st_dev,'ino':s.st_ino,'bytes':s.st_size,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'sha256':pin}
 finally:os.close(fd)
def inactive():
 for unit,data in units().items():
  old.read(old.UNIT/unit,0o644,hashlib.sha256(data).hexdigest())
  props={k:old.ctl('show',unit,'-p',k,'--value') for k in ('Names','LoadState','ActiveState','Job','FragmentPath','DropInPaths')}
  require(props=={'Names':unit,'LoadState':'loaded','ActiveState':'inactive','Job':'','FragmentPath':str(old.UNIT/unit),'DropInPaths':''},'SDK5 not inactive')
  if unit.endswith('.service'):require(old.ctl('show',unit,'-p','MainPID','--value')=='0','SDK5 service process remains')
def plan():
 require(os.geteuid()==0 and os.getegid()==0,'root required')
 require(not any(os.path.lexists(p) for p in (START,DONE,BACKUP,TEMP)),'guarded upgrade already attempted')
 old.directory(old.PREFIX,0,0,0o755);old.directory(STAGE,1000,1000,0o700)
 prior=identity(BIN,0,0o755,PRIOR_SHA);source=identity(SOURCE,1000,0o700,SOURCE_SHA);inactive()
 registry=old.read(old.ETC/'catalog-registry.json',0o644,'58a1d4f04a2a8ffe98424bd6e8c29b8a4491faac53346698e4f715017df04e78')
 canary_raw=old.read(CANARY,0o600);canary=json.loads(canary_raw)
 require(set(canary)=={'schema','positive','extra_connected_fd_denied','positive_invocation_id','negative_invocation_id','fixture_stopped','registration','original_attempt_retained'} and canary['schema']==1 and all(canary.get(k) is True for k in ('positive','extra_connected_fd_denied','fixture_stopped','original_attempt_retained')) and canary['registration'] is False,'native guard proof unavailable')
 original_raw=old.read(old.ETC/'sdk5-fdguard-canary-started.json',0o600);original=json.loads(original_raw)
 recovery=json.loads(old.read(old.ETC/'sdk5-fdguard-canary-recovery-started.json',0o600))
 require(original.get('binary',{}).get('sha256')==CANARY_BIN_SHA and recovery.get('original_intent_sha256')==hashlib.sha256(original_raw).hexdigest() and recovery.get('positive_invocation_id')==canary['positive_invocation_id'],'native guard provenance mismatch')
 return {'schema':1,'prior':prior,'source':source,'native_guard_receipt_sha256':hashlib.sha256(canary_raw).hexdigest(),'catalog_sha256':hashlib.sha256(registry).hexdigest(),'guard_source_sha256':GUARD_SHA,'entrypoint_sha256':ENTRY_SHA,'build_source_commit':COMMIT,'production_features':['registry-v5'],'canary_feature_enabled':False,'scope':'replace only inactive SDK5 executable; retain prior binary; no activation'}
def copy(src,uid,mode,pin,dest):
 before=identity(src,uid,mode,pin);a=os.open(src,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);b=None
 try:
  b=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  h=hashlib.sha256();total=0
  while chunk:=os.read(a,65536):
   total+=len(chunk);require(total<=before['bytes'],'copy grew');h.update(chunk);view=memoryview(chunk)
   while view:
    n=os.write(b,view);require(n>0,'short binary copy');view=view[n:]
  require(total==before['bytes'] and h.hexdigest()==pin,'copy changed');os.fchmod(b,0o755);old.noacl(b);os.fsync(b)
 finally:
  os.close(a)
  if b is not None:os.close(b)
 require(identity(src,uid,mode,pin)==before,'source changed during copy');identity(dest,0,0o755,pin);old.syncdir(dest.parent)
def apply(approved):
 require(plan()==approved,'guarded upgrade plan changed');old.store(START,canonical(approved),0o600)
 copy(BIN,0,0o755,PRIOR_SHA,BACKUP);copy(SOURCE,1000,0o700,SOURCE_SHA,TEMP)
 inactive();require(identity(BIN,0,0o755,PRIOR_SHA)==approved['prior'],'prior binary changed')
 os.replace(TEMP,BIN);old.syncdir(BIN.parent);identity(BIN,0,0o755,SOURCE_SHA);identity(BACKUP,0,0o755,PRIOR_SHA);inactive()
 receipt={'schema':1,'binary_path':str(BIN),'prior_binary_sha256':PRIOR_SHA,'binary_sha256':SOURCE_SHA,'guard_source_sha256':GUARD_SHA,'entrypoint_sha256':ENTRY_SHA,'build_source_commit':COMMIT,'production_features':['registry-v5'],'canary_feature_enabled':False,'native_guard_receipt_sha256':approved['native_guard_receipt_sha256'],'native_guard_binary_sha256':CANARY_BIN_SHA,'backup_path':str(BACKUP),'installed_inactive':True,'executed':False}
 old.store(DONE,canonical(receipt),0o600);return receipt
