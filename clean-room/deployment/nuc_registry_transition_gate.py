"""Source-only root registry transition gate. Not wired into production admission.

Every root catalog minter, grant issuer and launcher must hold admission() through
its critical section. A future upgrade coordinator must hold transition() and
publish a durable marker before mutating catalog or service state. Missing
integration means this module supplies no deployment authority.
"""
import contextlib,errno,fcntl,json,os,pathlib,re,stat
ROOT=pathlib.Path('/var/lib/software-factory-goose/registry-admission')
LOCK='gate.lock';MARKER='transition.json'

def require(value,msg):
 if not value:raise RuntimeError(msg)
def _json(raw):
 def unique(pairs):
  out={}
  for key,value in pairs:
   require(key not in out,'duplicate JSON field');out[key]=value
  return out
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('nonfinite JSON')))
def no_acl(fd,directory=False):
 for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(fd,name)
  except OSError as e:
   if e.errno==errno.ENODATA:continue
   raise RuntimeError('ACL unavailable') from None
  raise RuntimeError('ACL present')
def _directory(path,uid,gid,mode=0o700):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISDIR(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(uid,gid,mode),'gate directory unavailable');no_acl(fd,True);return fd
 except Exception:os.close(fd);raise
@contextlib.contextmanager
def _gate(path,exclusive,uid,gid=None,mode=0o700,lockmode=0o600):
 gid=uid if gid is None else gid
 d=_directory(path,uid,gid,mode);f=None
 try:
  f=os.open(LOCK,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=d);s=os.fstat(f)
  require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(uid,gid,1,lockmode),'gate lock unavailable');no_acl(f)
  fcntl.flock(f,(fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)|fcntl.LOCK_NB)
  # A symlink, partial or malformed marker is equally closed.
  try:os.stat(MARKER,dir_fd=d,follow_symlinks=False)
  except FileNotFoundError:pass
  else:raise RuntimeError('registry transition unresolved')
  yield d
 finally:
  if f is not None:os.close(f)
  os.close(d)
def _trusted_ancestors():
 for path in (pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),pathlib.Path('/var/lib/software-factory-goose')):
  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);require(st.st_uid==0 and st.st_gid==0 and not st.st_mode&0o022,'gate ancestor unavailable');no_acl(fd,True)
  finally:os.close(fd)
@contextlib.contextmanager
def admission():
 require(os.geteuid()==0,'root required');_trusted_ancestors()
 with _gate(ROOT,False,0,2000,0o710,0o440) as fd:
  verify_head();yield fd
@contextlib.contextmanager
def _transition(path,intent,uid,gid):
 require(isinstance(intent,dict) and set(intent)=={'schema','transition_id','old_manifest_sha256','new_manifest_sha256'} and type(intent['schema']) is int and intent['schema']==1 and intent['old_manifest_sha256']!=intent['new_manifest_sha256'] and all(isinstance(intent[k],str) and len(intent[k])==64 and all(c in '0123456789abcdef' for c in intent[k]) for k in ('old_manifest_sha256','new_manifest_sha256')) and isinstance(intent['transition_id'],str) and re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',intent['transition_id']) is not None,'invalid transition intent')
 with _gate(path,True,uid,gid) as d:
  raw=json.dumps(intent,sort_keys=True,separators=(',',':')).encode()+b'\n'
  f=os.open(MARKER,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=d)
  try:
   s=os.fstat(f);require((s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(uid,gid,1,0o600),'transition marker unavailable');no_acl(f)
   view=memoryview(raw)
   while view:
    n=os.write(f,view);require(n>0,'transition write failed');view=view[n:]
   os.fsync(f)
  finally:os.close(f)
  os.fsync(d)
  # The marker is deliberately permanent until a separately reviewed recovery
  # protocol establishes exact engine, journal, publication and attestation state.
  yield d

@contextlib.contextmanager
def _transition_already_locked(d,intent):
 require(isinstance(intent,dict) and set(intent)=={'schema','transition_id','old_manifest_sha256','new_manifest_sha256'} and type(intent['schema']) is int and intent['schema']==1 and intent['old_manifest_sha256']!=intent['new_manifest_sha256'] and all(isinstance(intent[k],str) and len(intent[k])==64 and all(c in '0123456789abcdef' for c in intent[k]) for k in ('old_manifest_sha256','new_manifest_sha256')) and isinstance(intent['transition_id'],str) and re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',intent['transition_id']) is not None,'invalid transition intent')
 raw=json.dumps(intent,sort_keys=True,separators=(',',':')).encode()+b'\n'
 f=os.open(MARKER,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=d)
 try:
  os.fchown(f,0,2000);os.fchmod(f,0o440);s=os.fstat(f);require((s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2000,1,0o440),'transition marker unavailable');no_acl(f)
  view=memoryview(raw)
  while view:
   n=os.write(f,view);require(n>0,'transition write failed');view=view[n:]
  os.fsync(f)
 finally:os.close(f)
 os.fsync(d)
 # The marker is deliberately permanent until a separately reviewed recovery
 # protocol establishes exact engine, journal, publication and attestation state.
 yield d

@contextlib.contextmanager
def transition(intent):
 require(os.geteuid()==0,'root required');_trusted_ancestors()
 # Hold exclusive lock and verify current head before reserving transition.
 with _gate(ROOT,True,0,2000,0o710,0o440) as fd:
  head=verify_head();require(intent.get('old_manifest_sha256')==head['manifest_sha256'],'transition baseline changed')
  with _transition_already_locked(fd,intent) as held:yield held

# Fixed-path completion is deliberately separate from transition(); it only consumes
# a root-owned replay receipt published by the separately reviewed replay producer.
# The producer, bootstrapping and service restart are not implemented in this module.
REGISTRY=pathlib.Path('/etc/software-factory-goose/catalog-registry.json')
ATTEST=pathlib.Path('/etc/software-factory-goose/registry-process-attestation.json')
PROBE=pathlib.Path('/usr/local/libexec/software-factory-goose/registry-attestor-probe')
PROBE_SHA='aa2868160da22acbdae103c118f952cc8d8675fe31b0558dec969c7f96b21642'
# No reviewed fixed history-replay producer is installed yet.
REPLAY_PRODUCER_SHA=None
REPLAY_PRODUCER=None

def _protected_read(path,mode,limit,gid=0):
 import hashlib
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,gid,1,mode) and 0<st.st_size<=limit,'protected record unavailable');no_acl(fd)
  b=bytearray()
  while len(b)<=limit:
   part=os.read(fd,min(65536,limit+1-len(b)))
   if not part:break
   b.extend(part)
  require(len(b)==st.st_size,'protected record changed');return bytes(b)
 finally:os.close(fd)
def _digest(raw):
 import hashlib
 return hashlib.sha256(raw).hexdigest()
def _atomic_head(directory,body):
 tmp='head.json.pending';f=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
 try:
  os.fchown(f,0,2000);os.fchmod(f,0o440);s=os.fstat(f);require((s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2000,1,0o440),'head temp unavailable');no_acl(f)
  view=memoryview(body)
  while view:
   n=os.write(f,view);require(n>0,'head write failed');view=view[n:]
  os.fsync(f)
 finally:os.close(f)
 os.fsync(directory);os.replace(tmp,'head.json',src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
def verify_history(oldraw,newraw,intent,replay):
 oldj=_json(oldraw);newj=_json(newraw)
 require(_digest(oldraw)==intent['old_manifest_sha256'] and _digest(newraw)==intent['new_manifest_sha256'] and isinstance(oldj,dict) and isinstance(newj,dict) and oldj.get('schema')==1 and newj.get('schema')==1 and isinstance(oldj.get('entries'),list) and isinstance(newj.get('entries'),list) and newj['entries'][:-1]==oldj['entries'] and len(newj['entries'])==len(oldj['entries'])+1 and len(oldj['entries'])==replay['prior_catalog_count'] and newj.get('active_intent')!=oldj.get('active_intent') and _digest(json.dumps(oldj['entries'],sort_keys=True,separators=(',',':')).encode())==replay['prior_catalogs_sha256'],'registry history mismatch')
def _store_history(hist,name,body):
 d=_directory(hist,0,0)
 try:
  f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=d)
  try:
   st=os.fstat(f);require((st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,0,1,0o600),'history metadata mismatch');no_acl(f)
   view=memoryview(body)
   while view:
    n=os.write(f,view);require(n>0,'history write failed');view=view[n:]
   os.fsync(f)
  finally:os.close(f)
  os.fsync(d)
 finally:os.close(d)
def resolve_deployment(plan,hist):
 """Read the server-minted ID for a one-shot upgrade, or a pinned existing ID."""
 name=plan['transition_id'];known=plan['new_deployment_id']
 if known is not None:
  require(isinstance(known,str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',known),'deployment unavailable');return known
 require(plan['new_sdk_uri']=='http://127.0.0.1:9085' and plan['old_sdk_uri']=='http://127.0.0.1:9084','unrecognized SDK upgrade')
 started_raw=_protected_read(hist/(name+'.registration-started.json'),0o600,16384);started=_json(started_raw)
 result=_json(_protected_read(hist/(name+'.registration-complete.json'),0o600,16384))
 require(set(result)=={'schema','transition_id','uri','deployment_id','invocation_id','binding_sha256'} and type(result['schema']) is int and result['schema']==1 and result['transition_id']==name and result['uri']==plan['new_sdk_uri'] and result['binding_sha256']==_digest(started_raw) and started.get('transition_id')==name and started.get('plan_sha256')==_digest(_protected_read(hist/(name+'.plan.json'),0o600,16384)) and started.get('new_manifest_sha256')==plan['new_manifest_sha256'] and started.get('uri')==plan['new_sdk_uri'] and isinstance(result['invocation_id'],str) and re.fullmatch(r'[0-9a-f]{32}',result['invocation_id']) and isinstance(result['deployment_id'],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',result['deployment_id']),'registration receipt unavailable')
 return result['deployment_id']
def registry_profile(registry_raw):
 import nuc_registry_attestation_profiles as profiles
 return profiles.select_for_registry(registry_raw,lambda path:_protected_read(path,0o644,65536))

def finish_transition(directory,intent):
 """Complete only the still-locked exact transition after trusted replay evidence.

 Caller must be inside transition(); a crash before the final unlink remains
 closed. Recovery of partial writes is deliberately not a generic marker clear.
 """
 import subprocess
 require(REPLAY_PRODUCER_SHA is not None and REPLAY_PRODUCER is not None,'reviewed replay producer unavailable')
 require(_digest(_protected_read(REPLAY_PRODUCER,0o755,100_000_000))==REPLAY_PRODUCER_SHA,'replay producer changed')
 name=intent['transition_id'];require(isinstance(name,str) and re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',name) is not None,'invalid transition id');marker=_protected_read(ROOT/MARKER,0o440,4096,2000)
 require(_json(marker)==intent,'transition marker changed')
 hist=ROOT/'history';_directory_fd=_directory(hist,0,0);os.close(_directory_fd)
 replay_raw=_protected_read(hist/(name+'.replay.json'),0o600,16384);replay=_json(replay_raw)
 required={'schema','transition_id','old_manifest_sha256','new_manifest_sha256','prior_catalogs_sha256','prior_catalog_count','replayed_catalog_count','deployment_id','attestation_sha256','producer_sha256','plan_sha256'}
 require(set(replay)==required and type(replay['schema']) is int and replay['schema']==1 and replay['producer_sha256']==REPLAY_PRODUCER_SHA and replay['transition_id']==name and replay['old_manifest_sha256']==intent['old_manifest_sha256'] and replay['new_manifest_sha256']==intent['new_manifest_sha256'] and isinstance(replay['prior_catalog_count'],int) and not isinstance(replay['prior_catalog_count'],bool) and 1<=replay['prior_catalog_count']<=16 and type(replay['replayed_catalog_count']) is int and replay['replayed_catalog_count']==replay['prior_catalog_count'] and isinstance(replay['deployment_id'],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',replay['deployment_id']) and isinstance(replay['prior_catalogs_sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',replay['prior_catalogs_sha256']),'replay proof invalid')
 plan_raw=_protected_read(hist/(name+'.plan.json'),0o600,16384);plan=_json(plan_raw);require(_digest(plan_raw)==replay['plan_sha256'] and plan.get('transition_id')==name and plan.get('old_manifest_sha256')==intent['old_manifest_sha256'] and plan.get('new_manifest_sha256')==intent['new_manifest_sha256'] and resolve_deployment(plan,hist)==replay['deployment_id'],'transition plan mismatch')
 oldraw=_protected_read(hist/(name+'.old-registry.json'),0o600,65536);registry=_protected_read(REGISTRY,0o644,65536);verify_history(oldraw,registry,intent,replay)
 profile=registry_profile(registry);att=_protected_read(profile['attestation'],0o600,16384);attj=_json(att);boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 require(_digest(registry)==intent['new_manifest_sha256'] and _digest(att)==replay['attestation_sha256'] and attj.get('boot_id')==boot and attj.get('config_sha256')==intent['new_manifest_sha256'],'new registry attestation mismatch')
 require(_digest(_protected_read(profile['probe'],0o755,10_000_000))==profile['probe_sha256'],'attestor changed')
 p=subprocess.run([str(profile['probe'])],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=50,check=False,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','SYSTEMD_IN_CHROOT':'0'})
 require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192 and _json(p.stdout)=={'service_attested':True,'grant_requested':False},'registry process attestation unavailable')
 if profile['profile']=='sdk5':
  pending_admission=__import__('nuc_registry_pending_admission')
  pending_admission.verify(__import__(__name__),intent,replay,attj,boot)
 result={'schema':1,'transition_id':name,'boot_id':boot,'manifest_sha256':intent['new_manifest_sha256'],'attestation_sha256':_digest(att),'replay_sha256':_digest(replay_raw),'intent_sha256':_digest(marker)}
 raw=json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n'
 _store_history(hist,name+'.intent.json',marker);_store_history(hist,name+'.complete.json',raw)
 head={'schema':1,'transition_id':name,'boot_id':boot,'manifest_sha256':intent['new_manifest_sha256'],'attestation_sha256':_digest(att),'completion_sha256':_digest(raw)}
 _atomic_head(directory,json.dumps(head,sort_keys=True,separators=(',',':')).encode()+b'\n')
 # Only after completion, head and directory durability. Any earlier failure retains marker.
 os.unlink(MARKER,dir_fd=directory);os.fsync(directory)
 return head

def verify_head():
 history_fd=_directory(ROOT/'history',0,0);os.close(history_fd)
 head=_json(_protected_read(ROOT/'head.json',0o440,16384,2000))
 require(set(head)=={'schema','transition_id','boot_id','manifest_sha256','attestation_sha256','completion_sha256'} and type(head['schema']) is int and head['schema']==1 and isinstance(head['transition_id'],str) and re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',head['transition_id']),'registry head unavailable')
 completion_raw=_protected_read(ROOT/'history'/(head['transition_id']+'.complete.json'),0o600,16384);completion=_json(completion_raw)
 require(set(completion)=={'schema','transition_id','boot_id','manifest_sha256','attestation_sha256','replay_sha256','intent_sha256'} and type(completion['schema']) is int and completion['schema']==1 and all(completion[k]==head[k] for k in ('transition_id','boot_id','manifest_sha256','attestation_sha256')) and _digest(completion_raw)==head['completion_sha256'],'registry completion mismatch')
 intent_raw=_protected_read(ROOT/'history'/(head['transition_id']+'.intent.json'),0o600,4096);replay_raw=_protected_read(ROOT/'history'/(head['transition_id']+'.replay.json'),0o600,16384);intent=_json(intent_raw)
 require(_digest(intent_raw)==completion['intent_sha256'] and _digest(replay_raw)==completion['replay_sha256'] and intent.get('transition_id')==head['transition_id'] and intent.get('new_manifest_sha256')==head['manifest_sha256'],'transition history mismatch')
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();reg=_protected_read(REGISTRY,0o644,65536);profile=registry_profile(reg);require(_digest(_protected_read(profile['probe'],0o755,10_000_000))==profile['probe_sha256'],'profile probe missing or changed');att=_protected_read(profile['attestation'],0o600,16384);attj=_json(att)
 require(head['boot_id']==boot and _digest(reg)==head['manifest_sha256'] and _digest(att)==head['attestation_sha256'] and attj.get('boot_id')==boot and attj.get('config_sha256')==head['manifest_sha256'],'registry head mismatch')
 return head
