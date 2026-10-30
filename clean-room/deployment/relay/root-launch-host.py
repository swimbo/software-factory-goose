#!/usr/bin/python3
"""Fixed root launch phases. Review only: no installer or socket entry point.

Only a root-authorized supervisor may call one fixed phase plus a generation.
Every unknown effect retains durable state. No provider key is read here.
"""
import contextlib,errno,fcntl,hashlib,importlib.util,json,os,pathlib,re,selectors,stat,subprocess,sys,time,types
ROOT=pathlib.Path('/etc/software-factory-goose');STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
PKG=pathlib.Path('/usr/local/libexec/software-factory-goose/relay');HANDOFF=pathlib.Path('/var/lib/software-factory-goose/handoff')
RUN=pathlib.Path('/run/software-factory-goose');SYSTEM=pathlib.Path('/etc/systemd/system')
CGROUP=pathlib.Path('/sys/fs/cgroup')
GOOSE=pathlib.Path('/usr/local/libexec/software-factory-goose/goose-protected-802d1478')
WORKER='sha256:509d7c54cfdbf6afd9e1c80ff924d367bdaf0979e6ef63b1f7d1134ce3a9710a'
WRITER='sha256:2efe778192492f6934540be9771bc1057b4724fe20bed6f71a362a4b91636b48'
GOOSE_SHA='802d1478e6a53ef7c68a56ccfed3aec59eab0afd68aa411ec0c1b516dc5334db'
WRITER_SHA='4ade60e556a391795b8f2b13a5e6d52efb68a04d6d806f5e0bf76e3cdc0d3d8c'
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C','SYSTEMD_IN_CHROOT':'0'}
DOCKER=['/usr/bin/docker','--host','unix:///run/docker.sock','--config','/run/software-factory-goose/docker-empty-config']
ID=re.compile(r'[0-7][0-9A-HJKMNP-TV-Z]{25}\Z');HEX=re.compile(r'[0-9a-f]{64}\Z')

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(x):return hashlib.sha256(x).hexdigest()
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise RuntimeError('duplicate field')
  d[k]=v
 return d

def no_acl(fd,directory=False):
 for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(fd,name)
  except OSError as e:
   if e.errno==errno.ENODATA:continue
   raise RuntimeError('ACL unavailable') from None
  raise RuntimeError('ACL present')

def directory(path,uid=0,gid=0,mode=None):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if s.st_uid!=uid or s.st_gid!=gid or (mode is not None and stat.S_IMODE(s.st_mode)!=mode) or s.st_mode&0o022:raise RuntimeError('directory identity mismatch')
  no_acl(fd,True);return (s.st_dev,s.st_ino)
 finally:os.close(fd)

def rootfile(path,mode=0o600,maximum=65536):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=mode or not 0<st.st_size<=maximum:raise RuntimeError('root file unavailable')
  no_acl(fd);data=bytearray()
  while len(data)<=maximum:
   piece=os.read(fd,min(1024*1024,maximum+1-len(data)))
   if not piece:break
   data.extend(piece)
  if len(data)!=st.st_size or len(data)>maximum:raise RuntimeError('root file changed')
  return bytes(data)
 finally:os.close(fd)

def load(path,mode=0o600):return json.loads(rootfile(path,mode),object_pairs_hook=unique,parse_constant=lambda x:(_ for _ in ()).throw(RuntimeError('nonfinite JSON')))
def root_hash(path,mode,maximum):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=mode or not 0<st.st_size<=maximum:raise RuntimeError('protected binary unavailable')
  no_acl(fd);h=hashlib.sha256();count=0
  while True:
   chunk=os.read(fd,1048576)
   if not chunk:break
   count+=len(chunk)
   if count>maximum:raise RuntimeError('protected binary oversized')
   h.update(chunk)
  if count!=st.st_size:raise RuntimeError('protected binary changed')
  return h.hexdigest()
 finally:os.close(fd)
def store(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  st=os.fstat(fd)
  if st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1:raise RuntimeError('record owner mismatch')
  no_acl(fd);view=memoryview(data)
  while view:
   n=os.write(fd,view)
   if n<=0:raise RuntimeError('record write failed')
   view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)

def fixed_run(argv,timeout=8,maxout=1048576):
 p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,close_fds=True)
 try:
  os.set_blocking(p.stdout.fileno(),False);sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ);buf=bytearray();end=time.monotonic()+timeout
  try:
   while sel.get_map():
    left=end-time.monotonic()
    if left<=0:raise RuntimeError('operation outcome unknown')
    for key,_ in sel.select(left):
     b=os.read(key.fd,min(65536,maxout+1-len(buf)))
     if not b:sel.unregister(p.stdout);continue
     buf.extend(b)
     if len(buf)>maxout:raise RuntimeError('operation outcome unknown')
   if p.wait(timeout=max(.01,end-time.monotonic()))!=0:raise RuntimeError('operation outcome unknown')
  finally:sel.close()
  return bytes(buf)
 finally:
  if p.poll() is None:
   p.kill()
   try:p.wait(timeout=2)
   except subprocess.TimeoutExpired:pass
  p.stdout.close()

def modules():
 for p in (pathlib.Path('/'),pathlib.Path('/etc'),ROOT,pathlib.Path('/usr'),pathlib.Path('/usr/local'),pathlib.Path('/usr/local/libexec'),PKG.parent,PKG):directory(p)
 manifest=load(ROOT/'relay-package.json');files=manifest.get('files') if isinstance(manifest,dict) else None
 if set(manifest)!={'schema','files'} or manifest['schema']!=1 or not isinstance(files,dict) or not {'nuc_root_deadline_arm.py','nuc_root_grant_deadline.py'}.issubset(files):raise RuntimeError('package manifest unavailable')
 sources={}
 for name,sha in files.items():
  if not isinstance(name,str) or not re.fullmatch(r'[a-z][a-z0-9_]*\.py',name) or not isinstance(sha,str) or not HEX.fullmatch(sha):raise RuntimeError('invalid package entry')
  raw=rootfile(PKG/name,0o444,1048576)
  if digest(raw)!=sha:raise RuntimeError('package digest mismatch')
  sources[name]=raw
 result={}
 for name in ('nuc_root_deadline_arm.py','nuc_root_grant_deadline.py'):
  module=types.ModuleType('rootfixed_'+name[:-3]);exec(compile(sources[name],'<root-protected-'+name+'>','exec'),module.__dict__);result[name]=module
 return result['nuc_root_deadline_arm.py'],result['nuc_root_grant_deadline.py']

def rooted(g):
 if not ID.fullmatch(g):raise RuntimeError('generation unavailable')
 for p in (pathlib.Path('/'),pathlib.Path('/etc'),ROOT,ROOT/'launch-catalog',ROOT/'tasks',ROOT/'relay-catalog',pathlib.Path('/var'),pathlib.Path('/var/lib'),STATE.parent,STATE,HANDOFF,HANDOFF/g):directory(p)
 directory(STATE,mode=0o700);directory(ROOT/'launch-catalog',mode=0o700);directory(ROOT/'tasks',mode=0o700);directory(ROOT/'relay-catalog',mode=0o700);directory(HANDOFF/g,mode=0o700)

def guard(g):
 if os.path.lexists(STATE/(g+'.closed')):raise RuntimeError('generation closed')
 armed=load(STATE/(g+'.deadline-armed.json'))
 if armed.get('target')!=g or armed.get('engine_effects') is not False or armed.get('boot_id')!=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() or time.time_ns()//1000000>=armed.get('expiry_ms',0) or time.monotonic_ns()>=armed.get('wake_monotonic_ns',0):raise RuntimeError('deadline unavailable')
 timer='sfactorydeadline'+g.lower()+'.timer';base=timer[:-6]
 active=fixed_run(['/usr/bin/systemctl','show',timer,'-p','ActiveState','--value'],timeout=4).decode().strip()
 wake=fixed_run(['/usr/bin/busctl','get-property','org.freedesktop.systemd1','/org/freedesktop/systemd1/unit/'+base+'_2etimer','org.freedesktop.systemd1.Timer','NextElapseUSecMonotonic'],timeout=4).decode().strip()
 if active!='active' or wake!='t '+str(armed['wake_monotonic_ns']//1000):raise RuntimeError('deadline manager unavailable')
 cg=CGROUP/('sfactory'+g.lower()+'.slice');record=load(ROOT/'tasks'/(g+'.json'))
 fd=os.open(cg,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);named=os.lstat(cg)
  if not stat.S_ISDIR(st.st_mode) or record.get('target_id')!=g or record.get('generation')!=g or record.get('boot_id')!=armed['boot_id'] or (st.st_dev,st.st_ino)!=(record.get('cgroup_dev'),record.get('cgroup_ino')) or (named.st_dev,named.st_ino)!=(st.st_dev,st.st_ino):raise RuntimeError('cgroup identity changed')
  def control(name):
   child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
   try:
    raw=os.read(child,1025)
    if len(raw)>1024:raise RuntimeError('cgroup control oversized')
    return raw
   finally:os.close(child)
  if control('cgroup.freeze').strip()!=b'0' or b'frozen 0' not in control('cgroup.events').splitlines():raise RuntimeError('cgroup unavailable')
 finally:os.close(fd)
 if time.monotonic_ns()>=armed['wake_monotonic_ns'] or time.time_ns()//1000000>=armed['expiry_ms'] or os.path.lexists(STATE/(g+'.closed')):raise RuntimeError('generation closed or expired')

def context(g,prod,need_timer=True):
 rooted(g)
 cat=load(ROOT/'launch-catalog'/(g+'.json'));recipe_raw=rootfile(ROOT/'launch-catalog'/(g+'.recipe.json'));recipe=json.loads(recipe_raw,object_pairs_hook=unique)
 if canonical(recipe)!=recipe_raw:raise RuntimeError('recipe not canonical')
 verified=load(STATE/(g+'.grant-verified'));stop=load(ROOT/'tasks'/(g+'.json'));boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 binding,expiry=prod.matches(cat,recipe,verified,stop,boot,g,time.time_ns()//1000000)
 if digest(recipe_raw)!=cat['recipe_sha256'] or not HEX.fullmatch(binding):raise RuntimeError('binding mismatch')
 request=rootfile(STATE/(g+'.grant-request'))
 if request!=(g+'\n'+cat['scope']['catalog_sha256']+'\n').encode():raise RuntimeError('request record mismatch')
 if need_timer:
  guard(g);armed=load(STATE/(g+'.deadline-armed.json'))
  if armed.get('binding_sha256')!=binding or armed.get('expiry_ms')!=expiry or armed.get('verified_grant_sha256')!=digest(rootfile(STATE/(g+'.grant-verified'))):raise RuntimeError('deadline binding mismatch')
 return cat,recipe,stop,binding

def mount_paths(g):
 return {'input':HANDOFF/g/'input','output':HANDOFF/g/'output','candidate':HANDOFF/g/'candidate','profile':ROOT/'relay-catalog'/(g+'.profile.json'),'prompt':ROOT/'relay-catalog'/(g+'.prompt.txt'),'socket':RUN/'relay'/g/'relay.sock','goose':GOOSE}

def secure_socket(path,gid):
 sock=os.lstat(path)
 if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid!=0 or sock.st_gid!=gid or stat.S_IMODE(sock.st_mode)!=0o660:raise RuntimeError('socket unavailable')
 try:os.getxattr(path,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:
  if e.errno!=errno.ENODATA:raise RuntimeError('socket ACL unavailable') from None
 else:raise RuntimeError('socket ACL present')
 return (sock.st_dev,sock.st_ino)

def callback_identity(g):
 parent=directory(RUN/'relay'/g,0,2000,0o710)
 return parent,secure_socket(mount_paths(g)['socket'],2001)

@contextlib.contextmanager
def callback_lifecycle(g):
 if not ID.fullmatch(g):raise RuntimeError('generation unavailable')
 directory(STATE,mode=0o700)
 fd=os.open(STATE/(g+'.callback-lifecycle.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))!=(0,0,1,0o600):raise RuntimeError('callback lock unavailable')
  no_acl(fd);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  os.fsync(fd);parent=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:os.fsync(parent)
  finally:os.close(parent)
  yield
 finally:os.close(fd)

def callback_rebind_allowed(g):
 # Call only while holding callback_lifecycle. Until a reviewed recovery
 # protocol proves all producers quiescent and engine operations reconciled,
 # any durable create intent permanently denies socket stop/rebind.
 if any(os.path.lexists(STATE/(g+'.'+suffix)) for suffix in ('host-create-intent.json','writer-create-intent.json','goose-create-intent.json')):
  raise RuntimeError('callback create may be unresolved; rebind denied')
 return True

def validate_inputs(g,recipe):
 p=mount_paths(g);dirs={}
 for name,uid in (('input',0),('output',2001),('candidate',2001)):
  dev,ino=directory(p[name],uid,uid,0o755);dirs[name+'_dir']={'path':str(p[name]),'dev':dev,'ino':ino}
 profile_raw=rootfile(p['profile'],0o444)
 if digest(profile_raw)!=recipe['profile_sha256'] or digest(rootfile(p['prompt'],0o444))!=recipe['prompt_sha256'] or root_hash(p['goose'],0o755,350*1024*1024)!=GOOSE_SHA:raise RuntimeError('worker artifact mismatch')
 profile=json.loads(profile_raw,object_pairs_hook=unique)
 keys=('purpose','generation','task_id','worker_uid','goose_binary_sha256','worker_image_id','worker_program_sha256','writer_image_id','writer_program_sha256','fixed_parent')
 core={k:recipe[k] for k in keys}
 if profile!={'schema':1,'profile':'nuc-root-supervised-stdio-v1','task_id':recipe['task_id'],'generation':g,'recipe_sha256':digest(canonical(core)),'worker_uid':2001}:raise RuntimeError('protected profile mismatch')
 for parent in (RUN,RUN/'relay'):directory(parent)
 directory(RUN/'relay'/g,0,2000,0o710)
 secure_socket(p['socket'],2001)
 return p,dirs

def expected_mounts(g,role):
 p=mount_paths(g)
 if role=='writer':return [{'source':str(p['candidate']),'destination':'/candidate','rw':True},{'source':str(p['input']),'destination':'/handoff/input','rw':False},{'source':str(p['output']),'destination':'/handoff/output','rw':True}]
 return [{'source':str(p['goose']),'destination':'/goose','rw':False},{'source':str(p['socket']),'destination':'/gate/relay.sock','rw':False},{'source':str(p['prompt']),'destination':'/factory/prompt.txt','rw':False},{'source':str(p['profile']),'destination':'/run/software-factory-goose/profile.json','rw':False}]

def docker_args(g,role):
 name='sfactory'+role+g.lower();image=WORKER if role=='goose' else WRITER
 args=DOCKER+['create','--name',name,'--label','org.software-factory.generation='+g,'--label','org.software-factory.role='+role,'--cgroup-parent','sfactory'+g.lower()+'.slice','--network','none','--cgroupns','private','--ipc','private','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','1g','--cpus','1','--restart','no','--user','2001:2001','--pull','never']
 for m in expected_mounts(g,role):args+=['--mount','type=bind,src='+m['source']+',dst='+m['destination']+('' if m['rw'] else ',readonly')]
 if role=='goose':args+=['--tmpfs','/work:rw,size=67108864,uid=2001,gid=2001,mode=0700']
 return args+[image]

def inspect(g,role,ident,expected_status):
 if not isinstance(ident,str) or not HEX.fullmatch(ident):raise RuntimeError('container id unavailable')
 objects=json.loads(fixed_run(DOCKER+['inspect',ident]),object_pairs_hook=unique)
 if len(objects)!=1:raise RuntimeError('container inspection ambiguous')
 o=objects[0];cfg=o['Config'];host=o['HostConfig'];state=o['State'];image=WORKER if role=='goose' else WRITER
 expected_entry=['/usr/local/bin/python3','-I','-B','/factory/'+('nuc_goose_worker.py' if role=='goose' else 'nuc_fixed_writer.py')]
 expected_env=['PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG=C.UTF-8','GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D','PYTHON_VERSION=3.11.18','PYTHON_SHA256=9120e0a653868f6e3698d36cdd99e5a58903ec9469e448f21d98f7b16d8fa290']
 if (o['Id']!=ident or o['Name']!='/sfactory'+role+g.lower() or o['Image']!=image or state['Status']!=expected_status or (expected_status=='created' and state['Pid']!=0) or cfg['User']!='2001:2001' or cfg.get('Entrypoint')!=expected_entry or cfg.get('Cmd') not in (None,[]) or cfg.get('Env')!=expected_env or (cfg.get('Labels') or {}).get('org.software-factory.generation')!=g or (cfg.get('Labels') or {}).get('org.software-factory.role')!=role or host['CgroupParent']!='sfactory'+g.lower()+'.slice' or host['NetworkMode']!='none' or host['CgroupnsMode']!='private' or host['IpcMode']!='private' or host.get('PidMode')!='' or host.get('UTSMode')!='' or host['ReadonlyRootfs'] is not True or host['Privileged'] is not False or host['CapDrop']!=['ALL'] or host.get('CapAdd') not in (None,[]) or host.get('Binds') not in (None,[]) or host.get('Devices') not in (None,[]) or host.get('DeviceRequests') not in (None,[]) or host.get('SecurityOpt') not in (['no-new-privileges'],['no-new-privileges:true']) or host['PidsLimit']!=64 or host['Memory']!=1073741824 or host['NanoCpus']!=1000000000 or host.get('RestartPolicy',{}).get('Name')!='no'):raise RuntimeError('container configuration mismatch')
 if role=='goose':
  if host.get('Tmpfs')!={'/work':'rw,size=67108864,uid=2001,gid=2001,mode=0700'}:raise RuntimeError('worker tmpfs mismatch')
 elif host.get('Tmpfs') not in (None,{}):raise RuntimeError('writer tmpfs mismatch')
 mounts=[]
 for m in o['Mounts']:
  if m.get('Type')!='bind' or type(m.get('RW')) is not bool:raise RuntimeError('mount unavailable')
  mounts.append({'source':m['Source'],'destination':m['Destination'],'rw':m['RW']})
 if sorted(mounts,key=lambda m:m['destination'])!=sorted(expected_mounts(g,role),key=lambda m:m['destination']):raise RuntimeError('mount mismatch')
 return o

def proc_protection(g,obj):
 pid=obj['State']['Pid']
 if type(pid) is not int or pid<=1:raise RuntimeError('process unavailable')
 fields=dict(line.split(':',1) for line in pathlib.Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line)
 if fields.get('Uid','').split()!=['2001']*4 or fields.get('Gid','').split()!=['2001']*4 or fields.get('NoNewPrivs','').strip()!='1' or fields.get('Seccomp','').strip()!='2' or any(int(fields[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapBnd','CapAmb')):raise RuntimeError('worker protection mismatch')
 lines=pathlib.Path('/proc/'+str(pid)+'/cgroup').read_text().splitlines()
 if len(lines)!=1 or not lines[0].startswith('0::/') or 'sfactory'+g.lower()+'.slice' not in lines[0][4:].split('/'):raise RuntimeError('worker cgroup mismatch')

def helper_records(g):
 x=load(STATE/(g+'.host-created.json'))
 if set(x)!={'schema','generation','binding_sha256','writer_id','goose_id'} or x['schema']!=1 or x['generation']!=g or not all(isinstance(x[k],str) and HEX.fullmatch(x[k]) for k in ('binding_sha256','writer_id','goose_id')):raise RuntimeError('created seal unavailable')
 return x

def engine_guard():
 directory(RUN/'docker-empty-config',mode=0o700)
 if any((RUN/'docker-empty-config').iterdir()):raise RuntimeError('Docker configuration not empty')
 fd=os.open('/usr/bin/docker',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  binary=os.fstat(fd)
  if not stat.S_ISREG(binary.st_mode) or binary.st_uid!=0 or binary.st_gid!=0 or binary.st_mode&0o022 or binary.st_nlink!=1:raise RuntimeError('Docker binary unavailable')
  no_acl(fd)
 finally:os.close(fd)
 daemon=os.lstat('/run/docker.sock')
 if not stat.S_ISSOCK(daemon.st_mode) or daemon.st_uid!=0:raise RuntimeError('Docker socket unavailable')
 if fixed_run(DOCKER+['info','--format','{{.ID}}']).decode().strip()!='56d25a60-5f64-4212-b904-e750067ac6a5' or fixed_run(DOCKER+['version','--format','{{.Server.GitCommit}}']).decode().strip()!='3ce5872' or fixed_run(DOCKER+['version','--format','{{.Server.Version}}']).decode().strip()!='29.8.0' or fixed_run(['/usr/bin/systemctl','show','docker.service','-p','MainPID','--value']).decode().strip()!='2145':raise RuntimeError('engine identity unavailable')
 original='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062'
 o=json.loads(fixed_run(DOCKER+['inspect',original]),object_pairs_hook=unique)
 if len(o)!=1 or o[0]['Id']!=original or o[0]['Name']!='/sf-owner-224a71d2db764249aa6cade3c1b39c80' or o[0]['State']['Status']!='created' or o[0]['State']['Pid']!=0 or (o[0]['Config'].get('Labels') or {}).get('org.software-factory.escape-spike')!='224a71d2db764249aa6cade3c1b39c80':raise RuntimeError('original guard unavailable')

def provenance(recipe):
 r=load(ROOT/'worker-images.json')
 if set(r)!={'schema','purpose','base_image_id','goose_sha256','worker','writer','engine_started'} or r['schema']!=1 or r['purpose']!='nuc-goose-write-files-images-v1' or r['goose_sha256']!=GOOSE_SHA or r['base_image_id']!='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937' or r['engine_started'] is not False:raise RuntimeError('image provenance unavailable')
 for role in ('worker','writer'):
  item=r[role]
  if set(item)!={'image_id','program_sha256','files_sha256'} or item['image_id']!=recipe[role+'_image_id'] or item['program_sha256']!=recipe[role+'_program_sha256']:raise RuntimeError('image provenance mismatch')

def validate_template(g,cat,recipe,raw):
 template=json.loads(raw,object_pairs_hook=unique)
 keys={'schema','request_contract','generation','task_id','request_sha256','allowed_models','provider_binding_sha256'}
 if set(template)!=keys or canonical(template)!=raw or digest(raw)!=recipe['relay_scope_template_sha256'] or template['schema']!=2 or template['request_contract']!='goose-turn-context-v1' or template['generation']!=g or template['task_id']!=cat['scope']['task_id'] or template['provider_binding_sha256']!=recipe['provider_binding_sha256'] or not isinstance(template['request_sha256'],str) or not HEX.fullmatch(template['request_sha256']) or template['allowed_models']!=['deepseek-v4-pro:0813','deepseek-v4.1-flash:1017','ollama-cloud/deepseek-v4-pro:0813','ollama-cloud/deepseek-v4.1-flash:1017']:raise RuntimeError('scope template mismatch')
 return template

def scope_template(g,cat,recipe,binding):
 base=ROOT/'relay-catalog';raw=rootfile(base/(g+'.template.json'));template=validate_template(g,cat,recipe,raw)
 provider=rootfile(base/(g+'.provider.json'))
 if digest(provider)!=recipe['provider_binding_sha256']:raise RuntimeError('provider binding mismatch')
 # Only a protected provider binding is read here; no provider secret is opened.
 value=json.loads(provider,object_pairs_hook=unique)
 if set(value)!={'schema','container_id','image_id','pid','network_device','network_inode','sandbox_key','port'} or value['schema']!=1 or value['port']!=8080 or not isinstance(value['container_id'],str) or not HEX.fullmatch(value['container_id']) or not isinstance(value['image_id'],str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',value['image_id']) or any(type(value[k]) is not int or value[k]<=0 for k in ('pid','network_device','network_inode')) or not isinstance(value['sandbox_key'],str) or not re.fullmatch(r'/(?:var/run|run)/docker/netns/[0-9a-f]{12,64}',value['sandbox_key']):raise RuntimeError('provider binding unavailable')
 actual=fixed_run(DOCKER+['inspect','--format','{{.Id}} {{.Image}} {{.State.Pid}} {{.State.Status}} {{.NetworkSettings.SandboxKey}}',value['container_id']])
 expected=f"{value['container_id']} {value['image_id']} {value['pid']} running {value['sandbox_key']}\n".encode()
 ns=os.stat(value['sandbox_key'])
 if actual!=expected or (ns.st_dev,ns.st_ino)!=(value['network_device'],value['network_inode']):raise RuntimeError('provider identity changed')
 result=dict(template);result['grant_sha256']=binding;result['catalog_sha256']=digest(rootfile(ROOT/'launch-catalog'/(g+'.json')))
 return result

def unit_names(g):
 return ['sfactorywriter'+g.lower()+'.socket','sfactorywriter'+g.lower()+'.service','sfactoryrelay'+g.lower()+'.socket','sfactoryrelay'+g.lower()+'.service']

def property_value(unit,key):return fixed_run(['/usr/bin/systemctl','show',unit,'-p',key,'--value'],timeout=6).decode().strip()
def validate_units(g,pre_start=True):
 manifest=load(ROOT/'relay-catalog'/(g+'.units.json'));names=unit_names(g)
 if set(manifest)!={'schema','generation','units'} or manifest['schema']!=1 or manifest['generation']!=g or not isinstance(manifest['units'],dict) or set(manifest['units'])!=set(names):raise RuntimeError('unit manifest mismatch')
 directory(SYSTEM)
 for name in names:
  if not isinstance(manifest['units'][name],str) or not HEX.fullmatch(manifest['units'][name]) or digest(rootfile(SYSTEM/name,0o644))!=manifest['units'][name]:raise RuntimeError('unit file mismatch')
  for k,v in (('LoadState','loaded'),('Names',name),('FragmentPath',str(SYSTEM/name)),('DropInPaths',''),('NeedDaemonReload','no'),('Job','')):
   if property_value(name,k)!=v:raise RuntimeError('unit manager identity mismatch')
  if name==names[1] and property_value(name,'Slice')!='system.slice':raise RuntimeError('writer broker slice mismatch')
  if name==names[3] and property_value(name,'Slice')!='sfactory'+g.lower()+'.slice':raise RuntimeError('relay slice mismatch')
 for name,user,group,script,tail in ((names[1],'root','root','nuc_root_writer_service.py',' '+g),(names[3],'sfgoose-control','sfgoose-control','nuc_relay_server.py','')):
  for k,v in (('User',user),('Group',group),('NoNewPrivileges','yes'),('CapabilityBoundingSet',''),('ExecStartPre',''),('ExecStartPost',''),('Environment',''),('EnvironmentFiles',''),('Restart','no')):
   if property_value(name,k)!=v:raise RuntimeError('service manager configuration mismatch')
  cmd=property_value(name,'ExecStart');prefix='{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+str(PKG/script)+tail+' ; ignore_errors=no ;'
  if not cmd.startswith(prefix) or cmd.count('{ path=')!=1:raise RuntimeError('service command mismatch')
 for name,path,group,fdname in ((names[0],str(RUN/'writer'/(g+'.sock')),'sfgoose-control','writer'),(names[2],str(RUN/'relay'/g/'relay.sock'),'sfgoose-worker','callback')):
  if property_value(name,'SocketUser')!='root' or property_value(name,'SocketGroup')!=group or property_value(name,'SocketMode')!='0660' or property_value(name,'FileDescriptorName')!=fdname or property_value(name,'Listen')!=path+' (Stream)':raise RuntimeError('socket unit configuration mismatch')
 if property_value(names[2],'ActiveState')!='active':raise RuntimeError('relay socket not active')
 if pre_start and any(property_value(names[i],'ActiveState')!='inactive' for i in (1,3)):raise RuntimeError('service already active or failed')
 return names

def verify_scope_file(g,scope):
 if rootfile(ROOT/'relay-catalog'/(g+'.scope.json'))!=canonical(scope):raise RuntimeError('published scope mismatch')

def created_file(g,role):return STATE/(g+'.'+role+'-created.json')
def read_created(g,role,binding):
 v=load(created_file(g,role))
 if set(v)!={'schema','generation','role','binding_sha256','id'} or v['schema']!=1 or v['generation']!=g or v['role']!=role or v['binding_sha256']!=binding or not isinstance(v['id'],str) or not HEX.fullmatch(v['id']):raise RuntimeError('container record unavailable')
 return v['id']

def create_role(g,role,binding):
 guard(g);engine_guard();store(STATE/(g+'.'+role+'-create-intent.json'),canonical({'schema':1,'generation':g,'role':role,'binding_sha256':binding}));guard(g)
 ident=fixed_run(docker_args(g,role),timeout=8).decode().strip()
 if not HEX.fullmatch(ident):raise RuntimeError('create outcome unknown')
 # Record the exact ID before any inspection or closure recheck.
 store(created_file(g,role),canonical({'schema':1,'generation':g,'role':role,'binding_sha256':binding,'id':ident}))
 guard(g);inspect(g,role,ident,'created');guard(g);return ident

def writer_seal(g,cat,recipe,stop,binding,writer,dirs):
 mounts=sorted(expected_mounts(g,'writer'),key=lambda m:m['destination'])
 return {'schema':1,'purpose':'nuc-fixed-file-writer-v1','generation':g,'task_id':cat['scope']['task_id'],'binding_sha256':binding,'boot_id':stop['boot_id'],'writer_container_id':writer,'writer_image_sha256':WRITER[7:],'writer_program_sha256':WRITER_SHA,'cgroup_dev':stop['cgroup_dev'],'cgroup_ino':stop['cgroup_ino'],'input_dir':dirs['input_dir'],'output_dir':dirs['output_dir'],'candidate_dir':dirs['candidate_dir'],'mounts_sha256':digest(canonical(mounts))}

def phase_verify(g,prod):
 cat,recipe,stop,binding=context(g,prod,False);provenance(recipe);validate_inputs(g,recipe)
 # The outer transaction re-verifies after start as well as before creation.
 # Only a previously fsynced writer-start intent permits the running stage.
 running=os.path.lexists(STATE/(g+'.writer-start-intent.json'))
 if running:
  ids=helper_records(g);intent=load(STATE/(g+'.writer-start-intent.json'))
  if intent!={'schema':1,'generation':g,'id':ids['writer_id'],'binding_sha256':binding} or ids['binding_sha256']!=binding:raise RuntimeError('writer start binding mismatch')
 validate_units(g,pre_start=not running)
 if os.path.lexists(STATE/(g+'.closed')):raise RuntimeError('generation closed')
 return {'binding_sha256':binding}

def phase_arm(g,deadline,prod):
 cat,recipe,stop,binding=context(g,prod,False);provenance(recipe)
 plan=prod.plan(deadline,g);armed=prod.arm(deadline,plan)
 if armed.get('binding_sha256')!=binding:raise RuntimeError('deadline binding mismatch')
 guard(g);return {'binding_sha256':binding,'armed':True}

def phase_create(g,prod):
 # Every trusted socket stop/rebind must take the same lock and reject an
 # unresolved create intent, even after this process exits and releases flock.
 with callback_lifecycle(g):
  cat,recipe,stop,binding=context(g,prod);provenance(recipe);_,dirs=validate_inputs(g,recipe);validate_units(g);scope=scope_template(g,cat,recipe,binding)
  socket_identity=callback_identity(g)
  if rootfile(STATE/(g+'.launch-consumed'))!=(g+'\n'+binding+'\n').encode():raise RuntimeError('outer consumption mismatch')
  store(STATE/(g+'.host-create-intent.json'),canonical({'schema':1,'generation':g,'binding_sha256':binding}));guard(g)
  store(ROOT/'relay-catalog'/(g+'.scope.json'),canonical(scope));guard(g)
  writer=create_role(g,'writer',binding)
  if callback_identity(g)!=socket_identity:raise RuntimeError('callback identity changed')
  goose=create_role(g,'goose',binding)
  if callback_identity(g)!=socket_identity:raise RuntimeError('callback identity changed')
  store(ROOT/'relay-catalog'/(g+'.writer.json'),canonical(writer_seal(g,cat,recipe,stop,binding,writer,dirs)));guard(g)
  store(STATE/(g+'.host-created.json'),canonical({'schema':1,'generation':g,'binding_sha256':binding,'writer_id':writer,'goose_id':goose}));guard(g)
  return {'id':goose}

def phase_verify_created(g,prod):
 cat,recipe,stop,binding=context(g,prod);provenance(recipe);_,dirs=validate_inputs(g,recipe);validate_units(g);scope=scope_template(g,cat,recipe,binding);verify_scope_file(g,scope)
 ids=helper_records(g)
 if ids['binding_sha256']!=binding or read_created(g,'writer',binding)!=ids['writer_id'] or read_created(g,'goose',binding)!=ids['goose_id']:raise RuntimeError('container seals differ')
 if rootfile(ROOT/'relay-catalog'/(g+'.writer.json'))!=canonical(writer_seal(g,cat,recipe,stop,binding,ids['writer_id'],dirs)):raise RuntimeError('writer seal mismatch')
 engine_guard();inspect(g,'writer',ids['writer_id'],'created');inspect(g,'goose',ids['goose_id'],'created');guard(g)
 return {'id':ids['goose_id']}

def start_container(g,role,ident,binding):
 guard(g);engine_guard();store(STATE/(g+'.'+role+'-start-intent.json'),canonical({'schema':1,'generation':g,'id':ident,'binding_sha256':binding}));guard(g)
 fixed_run(DOCKER+['start',ident],timeout=8);guard(g);obj=inspect(g,role,ident,'running');proc_protection(g,obj);guard(g)

def start_unit(g,unit,binding,expected_uid):
 guard(g);validate_units(g,pre_start=False)
 if property_value(unit,'ActiveState')!='inactive':raise RuntimeError('unit start collision')
 store(STATE/(g+'.'+unit+'.start-intent.json'),canonical({'schema':1,'generation':g,'unit':unit,'binding_sha256':binding}));guard(g)
 fixed_run(['/usr/bin/systemctl','start',unit],timeout=8);guard(g);validate_units(g,pre_start=False)
 if property_value(unit,'ActiveState')!='active':raise RuntimeError('unit start unresolved')
 if unit.endswith('.service'):
  pid=int(property_value(unit,'MainPID'))
  if pid<=1:raise RuntimeError('service PID unavailable')
  fields=dict(line.split(':',1) for line in pathlib.Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line)
  if fields.get('Uid','').split()!=[str(expected_uid)]*4 or fields.get('Gid','').split()!=[str(expected_uid)]*4 or fields.get('NoNewPrivs','').strip()!='1' or any(int(fields[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapBnd','CapAmb')):raise RuntimeError('service process identity unavailable')
 guard(g)

def phase_start(g,prod):
 cat,recipe,stop,binding=context(g,prod);provenance(recipe);_,dirs=validate_inputs(g,recipe);names=validate_units(g);scope=scope_template(g,cat,recipe,binding);verify_scope_file(g,scope)
 ids=helper_records(g)
 if ids['binding_sha256']!=binding or rootfile(STATE/(g+'.launch-seal'))!=(g+'\n'+binding+'\n'+ids['goose_id']+'\n').encode():raise RuntimeError('outer seal mismatch')
 if read_created(g,'writer',binding)!=ids['writer_id'] or read_created(g,'goose',binding)!=ids['goose_id']:raise RuntimeError('created identity mismatch')
 if rootfile(ROOT/'relay-catalog'/(g+'.writer.json'))!=canonical(writer_seal(g,cat,recipe,stop,binding,ids['writer_id'],dirs)):raise RuntimeError('writer seal mismatch')
 engine_guard();inspect(g,'writer',ids['writer_id'],'created');inspect(g,'goose',ids['goose_id'],'created');guard(g)
 start_container(g,'writer',ids['writer_id'],binding)
 # Socket may already be active only when its fixed unit was independently provisioned.
 if property_value(names[0],'ActiveState')!='active':start_unit(g,names[0],binding,0)
 directory(RUN/'writer',0,2000,0o710);secure_socket(RUN/'writer'/(g+'.sock'),2000)
 start_unit(g,names[1],binding,0);start_unit(g,names[3],binding,2000)
 start_container(g,'goose',ids['goose_id'],binding);guard(g)
 return {'id':ids['goose_id']}

def main():
 if os.getuid()!=0 or os.geteuid()!=0 or len(sys.argv)!=3 or sys.argv[1] not in ('verify','arm','create','verify-created','start') or not ID.fullmatch(sys.argv[2]):raise RuntimeError('fixed root phase and generation required')
 phase,g=sys.argv[1:];deadline,prod=modules()
 result={'verify':lambda:phase_verify(g,prod),'arm':lambda:phase_arm(g,deadline,prod),'create':lambda:phase_create(g,prod),'verify-created':lambda:phase_verify_created(g,prod),'start':lambda:phase_start(g,prod)}[phase]()
 print(json.dumps(result,sort_keys=True,separators=(',',':')))
if __name__=='__main__':main()
