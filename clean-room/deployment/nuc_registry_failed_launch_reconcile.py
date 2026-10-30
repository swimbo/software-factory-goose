"""Exact-generation stop/snapshot/reconciliation. Review only, no entry point.

PLAN is read-only. APPLY first performs the independent kernel stop. On every
missing, changed or ambiguous proof, the generation stays closed/frozen and no
unknown container is removed. Handoff and prior evidence are never deleted.
"""
import hashlib,json,os,pathlib,re,stat,subprocess,types
G='01M65RMR3F04YB1B016EBBSXGG';TASK='01M65RMR3FE6FQTFRBHERRHXRG';LOW=G.lower()
BOOT='98b86bb5-c04c-46f5-951d-22e497102f29';CG_DEV=29;CG_INO=7798759
ROOT=pathlib.Path('/etc/software-factory-goose');STATE=pathlib.Path('/var/lib/software-factory-goose/stop');HANDOFF=pathlib.Path('/var/lib/software-factory-goose/handoff')/G;RELAY=pathlib.Path('/var/lib/software-factory-goose/relay')/G
CG=pathlib.Path('/sys/fs/cgroup')/('sfactory'+LOW+'.slice');SYSTEM=pathlib.Path('/etc/systemd/system')
HELPER=pathlib.Path('/usr/local/libexec/software-factory-goose/root-launch-host.py');HELPER_SHA='604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e'
STOP=pathlib.Path('/usr/local/libexec/software-factory-goose/sfactory_deadline_kernel_stop');STOP_SHA='e286a8daab464f29e14e11beed0147cf24a11b585b4dfc50e48cb8615d0a325a'
CAT_SHA='49248005a91cdc0198c648ca60b26e153e1a7960ba9672bd1cce2e41ff99b07f'
DRIVER='sfactory-intloop-launch-'+LOW+'.service'
INTENT=STATE/(G+'.failed-reconcile-intent.json');RECEIPT=STATE/(G+'.failed-reconcile-complete.json')
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def fail(message):raise RuntimeError(message)
def read_root(path,limit=65536):
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>limit:fail('root record unavailable')
  noacl(fd);data=bytearray()
  while len(data)<=limit:
   b=os.read(fd,min(65536,limit+1-len(data)))
   if not b:break
   data.extend(b)
  if len(data)!=s.st_size:fail('root record changed')
  return bytes(data)
 finally:os.close(fd)
def noacl(fd,directory=False):
 import errno
 for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(fd,name)
  except OSError as e:
   if e.errno==errno.ENODATA:continue
   fail('ACL unavailable')
  fail('ACL present')
def load_root(path):return json.loads(read_root(path),object_pairs_hook=unique)
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:fail('duplicate JSON key')
  d[k]=v
 return d
def hashbytes(b):return hashlib.sha256(b).hexdigest()
def protected_file(path,mode,sha,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=mode or s.st_size>limit:fail('protected file unavailable')
  noacl(fd);h=hashlib.sha256();count=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   count+=len(b);h.update(b)
   if count>limit:fail('protected file oversized')
  if count!=s.st_size or h.hexdigest()!=sha:fail('protected file changed')
 finally:os.close(fd)
def helper():
 protected_file(HELPER,0o755,HELPER_SHA,1_000_000)
 # Source is authenticated above, then re-read and hashed before compilation.
 raw=HELPER.read_bytes()
 if hashbytes(raw)!=HELPER_SHA:fail('helper changed')
 m=types.ModuleType('pinned_root_launch_host');exec(compile(raw,'<pinned-root-helper>','exec'),m.__dict__);return m

def make_plan(host):
 if os.geteuid()!=0 or pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=BOOT:fail('boot or caller mismatch')
 for base in (STATE,ROOT/'tasks',STOP.parent):
  for path in (base,*base.parents):
   fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
   try:
    s=os.fstat(fd)
    if s.st_uid!=0 or s.st_gid!=0 or s.st_mode&0o022:fail('untrusted stop ancestor')
    noacl(fd,True)
   finally:os.close(fd)
 protected_file(STOP,0o755,STOP_SHA,100_000_000)
 if any(os.path.lexists(x) for x in (INTENT,RECEIPT)):fail('reconciliation already attempted')
 stop_raw=read_root(ROOT/'tasks'/(G+'.json'));stop=json.loads(stop_raw,object_pairs_hook=unique);st=os.lstat(CG)
 if stop.get('target_id')!=G or stop.get('task_id')!=TASK or stop.get('generation')!=G or stop.get('boot_id')!=BOOT or (stop.get('cgroup_dev'),stop.get('cgroup_ino'))!=(CG_DEV,CG_INO) or not stat.S_ISDIR(st.st_mode) or (st.st_dev,st.st_ino)!=(CG_DEV,CG_INO):fail('generation identity unavailable')
 return {'component':'registry-failed-launch-reconcile','source_sha256':host.source_digest,'generation':G,'boot_id':BOOT,'catalog_sha256':CAT_SHA,'stop_catalog_sha256':hashbytes(stop_raw),'cgroup_dev':CG_DEV,'cgroup_ino':CG_INO,'helper_sha256':HELPER_SHA,'stop_sha256':STOP_SHA,'scope':'failed launch: kernel stop first; preserve handoff; exact owned cleanup only on complete proof'}

def store_intent(obj):
 fd=os.open(INTENT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  st=os.fstat(fd)
  if st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:fail('intent metadata mismatch')
  noacl(fd);raw=json.dumps(obj,sort_keys=True,separators=(',',':')).encode();view=memoryview(raw)
  while view:
   n=os.write(fd,view)
   if n<=0:fail('intent write failed')
   view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)

def frozen_empty():
 st=os.lstat(CG)
 if not stat.S_ISDIR(st.st_mode) or (st.st_dev,st.st_ino)!=(CG_DEV,CG_INO):fail('cgroup identity changed')
 obs=load_root(STATE/(G+'.observation'));closed=read_root(STATE/(G+'.closed'),128)
 if closed!=(G+'\n').encode() or obs.get('target_id')!=G or obs.get('boot_id')!=BOOT or (obs.get('cgroup_dev'),obs.get('cgroup_ino'))!=(CG_DEV,CG_INO) or any(obs.get(k) is not True for k in ('observed','closed','frozen','empty')) or obs.get('engine_reconciled') is not False:fail('kernel observation unavailable')
 fd=os.open(CG,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if (s.st_dev,s.st_ino)!=(CG_DEV,CG_INO):fail('cgroup descriptor changed')
  def ctrl(n):
   f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
   try:return os.read(f,1025)
   finally:os.close(f)
  events=ctrl('cgroup.events');freeze=ctrl('cgroup.freeze')
  if len(events)>1024 or b'frozen 1' not in events.splitlines() or b'populated 0' not in events.splitlines() or freeze.strip()!=b'1':fail('kernel containment unavailable')
 finally:os.close(fd)

def driver_terminal(h,binding,goose):
 started=load_root(STATE/(G+'.intloop-launch-started.json'));failure=load_root(STATE/(G+'.intloop-launch-failure.json'))
 if started!={'generation':G,'binding_sha256':binding} or failure.get('stage')!='launch' or failure.get('exit_status')!=1 or failure.get('output_bound_exceeded') is not False:fail('failed launch acknowledgement unavailable')
 if os.path.lexists(STATE/(G+'.intloop-launch-complete.json')):fail('unexpected launch completion')
 for key,value in [('LoadState','loaded'),('Names',DRIVER),('Transient','yes'),('FragmentPath','/run/systemd/transient/'+DRIVER),('DropInPaths',''),('Job',''),('ActiveState','failed'),('MainPID','0'),('Result','exit-code'),('ExecMainStatus','1')]:
  if h.property_value(DRIVER,key)!=value:fail('failed launch producer not terminal')
 cmd=h.property_value(DRIVER,'ExecStart');prefix='{ path=/usr/local/libexec/software-factory-goose/root-launch ; argv[]=/usr/local/libexec/software-factory-goose/root-launch '+G+' ; ignore_errors=no ;'
 if not cmd.startswith(prefix) or cmd.count('{ path=')!=1:fail('launch unit command mismatch')
 cg=pathlib.Path('/sys/fs/cgroup/system.slice')/DRIVER
 if cg.exists() and (cg/'cgroup.events').read_text().splitlines().count('populated 0')!=1:fail('launch unit still populated')
 # A new or late start is ambiguous until separately reconciled.
 for suffix in ('goose-start-intent.json','sfactoryrelay'+LOW+'.socket.start-intent.json','sfactoryrelay'+LOW+'.service.start-intent.json'):
  if os.path.lexists(STATE/(G+'.'+suffix)):fail('unexpected later start intent')
 writer=load_root(STATE/(G+'.writer-start-intent.json'))
 if set(writer)!={'schema','generation','id','binding_sha256'} or writer['schema']!=1 or writer['generation']!=G or writer['binding_sha256']!=binding:fail('writer start intent mismatch')
 for name in h.unit_names(G)[:2]:
  intent=load_root(STATE/(G+'.'+name+'.start-intent.json'))
  if intent!={'schema':1,'generation':G,'unit':name,'binding_sha256':binding}:fail('writer unit intent mismatch')

def records(h):
 host=h.helper_records(G);binding=host['binding_sha256'];goose=host['goose_id'];writer=host['writer_id']
 if read_root(STATE/(G+'.launch-consumed'),256)!=(G+'\n'+binding+'\n').encode() or read_root(STATE/(G+'.launch-seal'),512)!=(G+'\n'+binding+'\n'+goose+'\n').encode():fail('outer binding mismatch')
 if h.read_created(G,'goose',binding)!=goose or h.read_created(G,'writer',binding)!=writer:fail('container records mismatch')
 if load_root(STATE/(G+'.writer-start-intent.json')).get('id')!=writer:fail('writer start id mismatch')
 seal=load_root(ROOT/'relay-catalog'/(G+'.writer.json'))
 if seal.get('writer_container_id')!=writer or seal.get('binding_sha256')!=binding or seal.get('generation')!=G or (seal.get('cgroup_dev'),seal.get('cgroup_ino'))!=(CG_DEV,CG_INO):fail('writer seal mismatch')
 driver_terminal(h,binding,goose)
 return binding,writer,goose

def stop_units(h,callback_only=False):
 manifest=load_root(ROOT/'relay-catalog'/(G+'.units.json'));names=h.unit_names(G)
 if set(manifest)!={'schema','generation','units'} or manifest['schema']!=1 or manifest['generation']!=G or set(manifest['units'])!=set(names):fail('unit manifest mismatch')
 # Keep the callback socket until both exact IDs are reconciled.
 order=(names[2],) if callback_only else (names[0],names[1],names[3])
 for name in order:
  expected=manifest['units'][name]
  if not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected):fail('bad unit hash')
  protected_file(SYSTEM/name,0o644,expected,65536)
  for key,value in [('LoadState','loaded'),('Names',name),('FragmentPath',str(SYSTEM/name)),('DropInPaths',''),('NeedDaemonReload','no'),('Job','')]:
   if h.property_value(name,key)!=value:fail('unit identity or job unresolved')
  state=h.property_value(name,'ActiveState')
  if state not in ('inactive','failed','active'):fail('unit state unresolved')
  if state=='active':
   h.store(STATE/(G+'.reconcile-'+name+'.intent'),h.canonical({'generation':G,'unit':name,'operation':'stop'}))
   h.fixed_run(['/usr/bin/systemctl','stop',name],timeout=15)
  if h.property_value(name,'ActiveState') not in ('inactive','failed') or h.property_value(name,'Job')!='':fail('unit stop unresolved')
  if name.endswith('.service'):
   if h.property_value(name,'MainPID')!='0':fail('service remains live')
   # Root writer broker is outside the worker slice, so its own cgroup must
   # also be empty before a candidate snapshot can become stable.
   path=pathlib.Path('/sys/fs/cgroup')/('system.slice' if name==names[1] else 'sfactory'+LOW+'.slice')/name
   if path.exists() and (path/'cgroup.events').read_text().splitlines().count('populated 0')!=1:fail('service cgroup still populated')
 frozen_empty()

def stop_deadline_units(h):
 timer='sfactorydeadline'+LOW+'.timer';service='sfactorydeadline'+LOW+'.service'
 def identity(name):
  load=h.property_value(name,'LoadState');active=h.property_value(name,'ActiveState');job=h.property_value(name,'Job');names=h.property_value(name,'Names')
  if names!=name or job!='':fail('deadline unit identity or job unresolved')
  if load=='not-found':
   if active!='inactive' or h.property_value(name,'FragmentPath')!='' or h.property_value(name,'DropInPaths')!='':fail('collected deadline state unresolved')
   return load,active
  if load!='loaded' or h.property_value(name,'Transient')!='yes' or h.property_value(name,'FragmentPath')!='/run/systemd/transient/'+name or h.property_value(name,'DropInPaths')!='':fail('deadline unit ownership unresolved')
  if name==timer and h.property_value(name,'Unit')!=service:fail('deadline timer target mismatch')
  if name==service:
   cmd=h.property_value(name,'ExecStart');prefix='{ path='+str(STOP)+' ; argv[]='+str(STOP)+' '+G+' ; ignore_errors=no ;'
   if not cmd.startswith(prefix) or cmd.count('{ path=')!=1:fail('deadline service command mismatch')
  return load,active
 load,state=identity(timer)
 if load=='loaded' and state=='active':
  h.store(STATE/(G+'.reconcile-deadline-timer.intent'),h.canonical({'generation':G,'unit':timer,'operation':'stop'}))
  h.fixed_run(['/usr/bin/systemctl','stop',timer],timeout=15)
  load,state=identity(timer)
 if state!='inactive':fail('deadline timer stop unresolved')
 load,state=identity(service)
 if state not in ('inactive','failed') or (load=='loaded' and h.property_value(service,'MainPID')!='0'):fail('deadline service still running')
 frozen_empty()

def remove_exact(h,role,ident):
 frozen_empty();h.engine_guard()
 # A direct successful full-ID inspect is required, followed by the fixed recipe check.
 values=json.loads(h.fixed_run(h.DOCKER+['inspect',ident]),object_pairs_hook=unique)
 if len(values)!=1:fail('container inspect ambiguous')
 st=values[0]['State'];status=st.get('Status')
 if status not in ('created','exited') or st.get('Pid')!=0 or st.get('Running') is not False:fail('container not stopped')
 h.inspect(G,role,ident,status);frozen_empty()
 h.store(STATE/(G+'.reconcile-'+role+'-remove-intent.json'),h.canonical({'generation':G,'role':role,'id':ident}))
 h.fixed_run(h.DOCKER+['rm',ident],timeout=8)
 p=subprocess.run(h.DOCKER+['inspect',ident],env=h.ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,check=False)
 if p.returncode==0 or len(p.stderr)>8192 or 'no such object' not in p.stderr.decode(errors='replace').lower():fail('container removal unknown')
 frozen_empty();h.engine_guard()
 h.store(STATE/(G+'.reconcile-'+role+'-removed.json'),h.canonical({'generation':G,'role':role,'id':ident,'absent':True}))

def apply(host,reviewed):
 if make_plan(host)!=reviewed:fail('reviewed plan changed')
 store_intent(reviewed)
 # This stop does not depend on a launch lock, broker, database or Docker.
 p=subprocess.run([str(STOP),G],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=False,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C'})
 if p.returncode:fail('independent kernel stop unresolved')
 frozen_empty()
 h=helper();h.rooted(G)
 if hashbytes(read_root(ROOT/'launch-catalog'/(G+'.json')))!=CAT_SHA:fail('launch catalogue changed')
 # Missing IDs, missing failed-launch proof or an active producer deny cleanup.
 # The independent kernel stop already completed; it never takes this lock.
 # All trusted callback lifecycle actors must take the same exclusive flock.
 with h.callback_lifecycle(G):
  binding,writer,goose=records(h);stop_units(h);frozen_empty()
  remove_exact(h,'writer',writer);remove_exact(h,'goose',goose);frozen_empty()
  # Re-read producer termination and engine identity after both removals. Any
  # timeout, missing receipt or changed identity leaves the callback bound.
  driver_terminal(h,binding,goose);h.engine_guard();frozen_empty()
  h.store(STATE/(G+'.callback-stop-authorized.json'),h.canonical({'schema':1,'generation':G,'binding_sha256':binding,'writer_id':writer,'goose_id':goose,'exact_ids_removed':True,'producer_terminal':True}))
  stop_units(h,callback_only=True);stop_deadline_units(h)
 # Keep the empty frozen slice and durable closure; later recovery may reconcile
 # pending-start fences and exact unit history independently.
 h.store(RECEIPT,h.canonical({'schema':1,'generation':G,'binding_sha256':binding,'writer_id':writer,'goose_id':goose,'candidate_snapshot':'not attempted','kernel_closed_frozen_empty':True,'exact_ids_removed':True,'slice_retained_frozen':True,'engine_reconciled_for_exact_ids':True}))
 return {'generation':G,'kernel_closed_frozen_empty':True,'candidate_snapshot':'not attempted','exact_ids_removed':True,'slice_retained_frozen':True,'engine_reconciled_for_exact_ids':True}
