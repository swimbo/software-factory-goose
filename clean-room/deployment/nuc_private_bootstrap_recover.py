#!/usr/bin/env python3
"""One-shot recovery of the precisely inventoried failed private canary.

No initdb, createdb, journal reset, existing state deletion, retry, or production
activation. The root-created intent and backups survive every partial failure.
Requires review and the separate resource-limit operation before use.
"""
import errno,hashlib,json,os,pathlib,pwd,re,secrets,stat,subprocess,sys,time
PREFIX=pathlib.Path('/usr/local/libexec/software-factory-goose')
PG=PREFIX/'postgresql17'
ETC=pathlib.Path('/etc/software-factory-goose')
STATE=pathlib.Path('/var/lib/software-factory-goose/journal')
RUN=pathlib.Path('/run/software-factory-goose')
UNIT=pathlib.Path('/etc/systemd/system')
NAME='software-factory-goose-private-'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','HOME':'/nonexistent'}
SYSTEM_ID='7702303394074795435'; PG_INODE=(66306,19138550); SOCKET_INODE=(66306,19138868)
OLD={'private-runtime':'89002dbadf6eb1b0666247959bddbd8fa440a89b5d763c849465c11447fc471e',
 'private-genesis':'7d6a3d4b67bc6f748ba45505fb96e40a0142655c7b9ddaafeba423b78bc9b6dc',
 'private-restate':'a45eba5044e331636b9da5a8f37fc901dec4cd3ccfcb10889241f76fe9c209db',
 'private-netns-anchor.py':'3eb0162f005b961be44c381e142d16dc7ded34b2d5eca81ab9f7373fc1858123',
 'private-register.py':'0f82712ecce31ff0985e265ab12e286bf5b3132730c43a473502686478daf244'}
NEW={'private-runtime':('/tmp/sfactory-runtime-build.PjU7pCOX/stripped/private_runtime.opath','9ca260b3aebcfcd082ac6521825b20a4312b2ec991ab03a957ea89ffa6288082'),
 'private-genesis':('/tmp/sfactory-runtime-build.PjU7pCOX/stripped/private_genesis.opath','358e9a879328d286464354f98ce48882dac5f4756262be0330fc76fdbc25430e')}
START_HASH='9f5b346dee184d7384ff8b581f3f5b7e539275d0d97999b049a054e1e2487833'
CONFIG_HASH='53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6'
EVIDENCE_HASH='b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a'
ANCHOR_HASH={'host':'aa822f06d5353d586f36918436faad3c6ddf040fbb007bc37c92e37620ceae54','private':'2041226ae249df4b8e3f3514912785f99527878ea93c8906c5298304dcd31970'}
UNIT_SHA={'host-net.service': '86facd848497e5d32376ddbc0c494aa493445739728787a88f799971d39e38e3', 'net.service': 'cc52bf8108541f2b8b57ab2c2c8eb150ec803127d06d6dda6dc93de1252f5727', 'initdb.service': '4f599b07444e2960e3bc267f2f8cb975549c09b575b85aaee2e85966a554d1fb', 'postgres.service': 'f0bd0aa9150215fc43d05c124c36160a1e7559c919731e4818f59e67d77bcfa6', 'createdb.service': 'fb64be189c72fa3207c192a6c7dc86af1f599839e0ced6378e5c2e60310d478a', 'genesis.service': '5e6a38dc54f47e85fe6d5e3861fbc893081cc83cb868d80342bcb5ea9b737493', 'restate.service': '29d77496a0d3c3b67fc7c5a31b16654fd86dcec1505273ce70919f594756a8ae', 'intake.socket': '6a163dc05e354118272cc04671282a7a0c31cf72f7a0f2243edda5b180928088', 'worker.socket': 'e7c08c196e30c821bc714923b89b3d21dad8fea68602733f19b8c0310ccd1cc5', 'runtime.service': '5fe9af9180d08242e40614a5b1994ea3b4933bc92694b28abf8d48fcc69e3ebe', 'register.service': '20c04a7460a6b3851ffa9906bbb136639c76b636594346f17f22e3621b158249'}
LIMITS={'host-net.service': ('64M', 16, '50%'), 'net.service': ('64M', 16, '50%'), 'initdb.service': ('1G', 64, '100%'), 'postgres.service': ('1G', 128, '200%'), 'createdb.service': ('64M', 16, '50%'), 'genesis.service': ('512M', 64, '100%'), 'restate.service': ('4G', 256, '200%'), 'runtime.service': ('512M', 128, '100%'), 'register.service': ('64M', 16, '50%')}
INTENT=ETC/'private-recovery-started.json';DONE=ETC/'private-recovery-complete.json'
OWNED=False

def require(value,message):
 if not value:raise RuntimeError(message)
def noacl(fd,dir=False):
 for attr in (('system.posix_acl_access','system.posix_acl_default') if dir else ('system.posix_acl_access',)):
  try:os.getxattr(fd,attr)
  except OSError as e:require(e.errno==errno.ENODATA,'ACL unavailable')
  else:raise RuntimeError('ACL forbidden')
def directory(path,uid,gid,mode,identity=None):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require((s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(uid,gid,mode),'directory mismatch')
  if identity:require((s.st_dev,s.st_ino)==identity,'directory identity changed')
  noacl(fd,True);return {'dev':s.st_dev,'ino':s.st_ino,'uid':uid,'gid':gid,'mode':mode}
 finally:os.close(fd)
def read(path,mode=0o644,expected=None,maxsize=1_000_000):
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode and s.st_size<=maxsize,'file identity mismatch')
  noacl(fd);data=bytearray()
  while len(data)<=maxsize:
   part=os.read(fd,min(65536,maxsize+1-len(data)))
   if not part:break
   data.extend(part)
  digest=hashlib.sha256(data).hexdigest();require(len(data)==s.st_size and (expected is None or digest==expected),'file hash mismatch')
  return bytes(data),{'dev':s.st_dev,'ino':s.st_ino,'sha256':digest,'size':s.st_size}
 finally:os.close(fd)
def hash_source(path,expected,owner=None,mode=None,dest=None):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);out=None
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=300_000_000,'binary source mismatch')
  if owner is not None:require(s.st_uid==owner and s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode,'installed binary metadata mismatch');noacl(fd)
  if dest is not None:out=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o755)
  h=hashlib.sha256();total=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   total+=len(b);require(total<=s.st_size,'binary source grew');h.update(b)
   if out is not None:
    view=memoryview(b)
    while view:
     n=os.write(out,view);require(n>0,'short copy');view=view[n:]
  require(total==s.st_size and h.hexdigest()==expected,'binary hash mismatch')
  if out is not None:os.fchmod(out,0o755);os.fsync(out)
  return {'dev':s.st_dev,'ino':s.st_ino,'size':s.st_size,'sha256':expected}
 finally:
  if out is not None:os.close(out)
  os.close(fd)
def syncdir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def store(path,data,mode=0o600):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 try:
  os.fchmod(fd,mode);view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 syncdir(path.parent)
def systemctl(*args):
 p=subprocess.run(['/usr/bin/systemctl',*args],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
 require(p.returncode==0 and len(p.stdout)<=16384 and len(p.stderr)<=16384,'systemd outcome unavailable: '+args[0])
 return p.stdout.decode().strip()
def postgres_id():
 env={**ENV,'LD_LIBRARY_PATH':str(PG/'lib')}
 p=subprocess.run([str(PG/'bin/pg_controldata'),str(STATE/'pgdata')],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
 require(len(p.stdout)<=65536 and len(p.stderr)<=8192,'PG identity output limit')
 v=[x.split(':',1)[1].strip() for x in p.stdout.decode().splitlines() if x.startswith('Database system identifier:')]
 require(v==[SYSTEM_ID],'PG system identity mismatch')
 return v[0]
def verify_journal_auth():
 expected={'pg_hba.conf':'fdec6503318f5d528bfc4638df059025495eb71fd8ed59eac479f8f500c7db34',
           'pg_ident.conf':'14c50492faad7a7d1774845e3494f87acca0d5219c3569f34e1f4612b3614066'}
 for name,digest in expected.items():
  path=STATE/'pgdata'/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==2004 and st.st_gid==2004 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=4096,'PG auth config metadata mismatch')
   noacl(fd);body=os.read(fd,4097);require(len(body)==st.st_size and hashlib.sha256(body).hexdigest()==digest,'PG auth config changed')
  finally:os.close(fd)

def verify_postgres_tree():
 digest='00052a70c5265a5748f51fef235c1c7f6c0fcf7f0d2fd267f71c533e47f4dfc8'
 raw,_=read(ETC/'postgres-hardened-manifest.json',0o600,digest,maxsize=2_000_000)
 receipt,_=read(ETC/'postgres-harden-complete.json',0o600,maxsize=1024);receipt=json.loads(receipt)
 root=directory(PG,0,0,0o755)
 require(receipt=={'format':1,'source_manifest_sha256':'39216b7ac1e082074b9e6098e5a3c94a0d706a1910cc302b9df0eddd4d9d23e5','hardened_manifest_sha256':digest,'directory_count':62,'tree_dev':root['dev'],'tree_ino':root['ino']},'PG hardening receipt mismatch')
 manifest=json.loads(raw);require(manifest.get('format')==1,'PG manifest mismatch');entries=manifest['entries'];expected={e['path'] for e in entries}
 require(len(expected)==len(entries),'duplicate PG entry')
 found=set()
 for parent,dirs,files in os.walk(PG,followlinks=False):
  prefix=pathlib.Path(parent).relative_to(PG)
  for name in dirs+files:found.add(str(prefix/name))
 require(found==expected,'installed PG entry set mismatch')
 for e in entries:
  p=PG/e['path'];st=os.lstat(p);mode=int(e['mode'],8)
  require(st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==mode,'installed PG metadata mismatch')
  if e['type']=='symlink':
   require(stat.S_ISLNK(st.st_mode) and os.readlink(p)==e['target'] and '/' not in e['target'],'installed PG link mismatch')
  elif e['type']=='directory':directory(p,0,0,mode);require(not mode&0o022,'installed PG directory writable')
  else:
   require(e['type']=='file' and not mode&0o022,'installed PG entry unsafe')
   info=hash_source(p,e['sha256'],0,mode);require(info['size']==e['size'],'installed PG size mismatch')
 return digest


def dropin(name):
 memory,tasks,cpu=LIMITS[name];return f'[Service]\nMemoryMax={memory}\nTasksMax={tasks}\nCPUQuota={cpu}\n'.encode()
def verify_loaded_units():
 for name in UNIT_SHA:
  raw=systemctl('show',NAME+name,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec','--no-pager')
  values={}
  for line in raw.splitlines():
   key,sep,value=line.partition('=');require(sep and key not in values,'loaded unit parse failure');values[key]=value
  require(values.get('LoadState')=='loaded' and values.get('ActiveState') in ('inactive','failed') and values.get('FragmentPath')==str(UNIT/(NAME+name)) and values.get('Names')==NAME+name,'loaded unit identity mismatch')
  if name not in LIMITS:
   require(values.get('DropInPaths','')=='','unexpected socket drop-in');continue
  mem,tasks,cpu=LIMITS[name];expected=int(mem[:-1])*{'M':1024**2,'G':1024**3}[mem[-1]]
  text=values.get('CPUQuotaPerSecUSec','');match=re.fullmatch(r'([0-9]+)(us|ms|s|min|h)',text)
  require(match is not None,'CPU quota format unknown')
  duration=int(match.group(1))*{'us':1,'ms':1000,'s':1000000,'min':60000000,'h':3600000000}[match.group(2)]
  require(values.get('MainPID')=='0' and values.get('DropInPaths')==str(UNIT/(NAME+name+'.d')/'50-resources.conf') and values.get('MemoryMax')==str(expected) and values.get('TasksMax')==str(tasks) and duration==int(cpu[:-1])*10000,'loaded resource mismatch')


def preflight():
 require(os.geteuid()==0,'root required')
 for path,uid,gid,mode,identity in [(pathlib.Path('/'),0,0,0o755,None),(pathlib.Path('/etc'),0,0,0o755,None),(ETC,0,0,0o711,None),
  (pathlib.Path('/usr'),0,0,0o755,None),(pathlib.Path('/usr/local'),0,0,0o755,None),(pathlib.Path('/usr/local/libexec'),0,0,0o755,None),(PREFIX,0,0,0o755,None),
  (pathlib.Path('/var'),0,0,0o755,None),(pathlib.Path('/var/lib'),0,0,0o755,None),(pathlib.Path('/var/lib/software-factory-goose'),0,0,0o711,None),
  (STATE,2004,2004,0o700,None),(STATE/'pgdata',2004,2004,0o700,PG_INODE),(STATE/'socket',2004,2004,0o700,SOCKET_INODE),
  (pathlib.Path('/run'),0,0,0o755,None),(RUN,0,0,0o755,None),(pathlib.Path('/etc/systemd'),0,0,0o755,None),(UNIT,0,0,0o755,None),
  (pathlib.Path('/tmp'),0,0,0o1777,None),(pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX'),1000,1000,0o700,None),(pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX/stripped'),1000,1000,0o700,None)]:directory(path,uid,gid,mode,identity)
 for role,uid in [('sfgoose-control',2000),('sfgoose-worker',2001),('sfgoose-eval',2002),('sfgoose-brake',2003),('sfgoose-journal',2004)]:
  item=pwd.getpwnam(role);require((item.pw_uid,item.pw_gid,item.pw_shell)==(uid,uid,'/usr/sbin/nologin'),'role mismatch')
 verify_postgres_tree();verify_journal_auth()
 require(set(os.listdir(STATE))=={'pgdata','socket'},'journal differs from failed attempt')
 require(not list((STATE/'socket').iterdir()),'old PG socket or files remain')
 for path in (INTENT,DONE,ETC/'private-genesis.json',ETC/'private-bootstrap-complete',STATE/'private-genesis-started',STATE/'private-genesis-complete',STATE/'restate',RUN/'intake.sock',RUN/'worker.sock'):
  require(not os.path.lexists(path),'unexpected state; reconcile')
 backups=[ETC/'private-recovery-runtime.before',ETC/'private-recovery-host-anchor.before',ETC/'private-recovery-private-anchor.before',PREFIX/'private-runtime.before',PREFIX/'private-genesis.before',RUN/'host-netns.failed',RUN/'private-netns.failed',ETC/'private-runtime.recovery-new',PREFIX/'private-runtime.recovery-new',PREFIX/'private-genesis.recovery-new']
 require(not any(os.path.lexists(p) for p in backups),'recovery path occupied')
 started,started_info=read(ETC/'private-bootstrap-started',0o600,START_HASH);started=json.loads(started)
 require(set(started)=={'nonce','machine_sha256','state'} and started['state']=='started' and len(started['nonce'])==64,'original bootstrap intent mismatch')
 require(started['machine_sha256']==hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes().strip()).hexdigest(),'machine mismatch')
 cfg,cfg_info=read(ETC/'runtime.json',0o644,CONFIG_HASH);cfg=json.loads(cfg)
 require(cfg['boot_id']==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'boot mismatch')
 _,ev=read(ETC/'evidence.json',0o644,EVIDENCE_HASH)
 require(cfg['evidence_sha256']==ev['sha256'],'evidence mismatch')
 anchors={}
 for role in ('host','private'):
  raw,info=read(RUN/(role+'-netns.json'),0o600,ANCHOR_HASH[role]);obj=json.loads(raw)
  require(obj['role']==role and obj['uid']==0 and obj['version']==1,'old anchor mismatch')
  anchors[role]={'metadata':info,'observation':obj}
 require((anchors['host']['observation']['netns_dev'],anchors['host']['observation']['netns_ino'])==(cfg['host_namespace_dev'],cfg['host_namespace_ino']),'old host binding mismatch')
 require((anchors['private']['observation']['netns_dev'],anchors['private']['observation']['netns_ino'])==(cfg['namespace_dev'],cfg['namespace_ino']),'old private binding mismatch')
 binary={name:hash_source(PREFIX/name,digest,0,0o755) for name,digest in OLD.items()}
 proposed={name:hash_source(path,digest) for name,(path,digest) in NEW.items()}
 require(read(ETC/'private-resource-limits-complete.json',0o600)[0]==b'resource drop-ins installed; no units started\n','resource receipt mismatch')
 for name,digest in UNIT_SHA.items():
  read(UNIT/(NAME+name),0o644,digest,maxsize=16384)
  active=systemctl('show',NAME+name,'--property=ActiveState','--value');require(active in ('inactive','failed'),'unit not stopped')
  if name in LIMITS:
   directory(UNIT/(NAME+name+'.d'),0,0,0o755)
   require(os.listdir(UNIT/(NAME+name+'.d'))==['50-resources.conf'],'unexpected resource drop-in')
   data,_=read(UNIT/(NAME+name+'.d')/'50-resources.conf',0o644,maxsize=4096);require(data==dropin(name),'resource limit mismatch')
 verify_loaded_units()
 require(postgres_id()==SYSTEM_ID,'PG system mismatch')
 return {'format':1,'scope':'failed canary only; no initdb or createdb','machine_sha256':started['machine_sha256'],'boot_id':cfg['boot_id'],
  'bootstrap_nonce':started['nonce'],'start':started_info,'config':cfg_info,'anchors':anchors,'pg_system_id':SYSTEM_ID,'pgdata_dev':PG_INODE[0],'pgdata_ino':PG_INODE[1],
  'socket_dev':SOCKET_INODE[0],'socket_ino':SOCKET_INODE[1],'old_binaries':binary,'new_binaries':proposed}

def verify_genesis_receipts():
 for name,expected in [('private-genesis-started',b'genesis started; never automatically replay\n'),('private-genesis-complete',b'fresh projection genesis completed\n')]:
  path=STATE/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==2004 and st.st_gid==2004 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and os.read(fd,129)==expected,'genesis receipt mismatch');noacl(fd)
  finally:os.close(fd)


def new_anchor(role):
 unit=NAME+('host-net.service' if role=='host' else 'net.service')
 pid=int(systemctl('show',unit,'--property=MainPID','--value'))
 path=RUN/(role+'-netns.json')
 for _ in range(100):
  if path.exists():break
  time.sleep(.05)
 raw,info=read(path,0o600,maxsize=1024);obj=json.loads(raw)
 require(obj.get('role')==role and obj.get('uid')==0 and obj.get('version')==1 and obj.get('pid')==pid and pid>1 and obj.get('netns_ino',0)>0,'new anchor mismatch')
 require(systemctl('is-active',unit)=='active','anchor inactive')
 return obj

def replace_binary(name,plan):
 old=PREFIX/name;source,digest=NEW[name]
 # Preserve original bytes in a root-only backup before the new binary is installed.
 old_info=hash_source(old,OLD[name],0,0o755)
 require(old_info==plan['old_binaries'][name],'old binary changed')
 backup=PREFIX/(name+'.before');hash_source(old,OLD[name],0,0o755,backup)
 os.chmod(backup,0o600);fd=os.open(backup,os.O_RDONLY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd);syncdir(PREFIX)
 new=PREFIX/(name+'.recovery-new');info=hash_source(source,digest,dest=new)
 require(info==plan['new_binaries'][name],'new binary identity changed');syncdir(PREFIX)
 require(hash_source(old,OLD[name],0,0o755)==old_info,'old binary changed before replacement')
 os.replace(new,old);syncdir(PREFIX)

def apply(approved):
 global OWNED
 require(preflight()==approved,'reviewed recovery plan changed')
 recovery_nonce=secrets.token_hex(32)
 store(INTENT,json.dumps({'plan':approved,'recovery_nonce':recovery_nonce},sort_keys=True,separators=(',',':')).encode()+b'\n')
 OWNED=True
 raw_cfg,cfg_info=read(ETC/'runtime.json',0o644,CONFIG_HASH);require(cfg_info==approved['config'],'old config changed')
 store(ETC/'private-recovery-runtime.before',raw_cfg)
 old_anchors={}
 for role in ('host','private'):
  raw,info=read(RUN/(role+'-netns.json'),0o600,ANCHOR_HASH[role]);require(info==approved['anchors'][role]['metadata'],'old anchor changed')
  old_anchors[role]=json.loads(raw);store(ETC/('private-recovery-'+role+'-anchor.before'),raw)
  os.rename(RUN/(role+'-netns.json'),RUN/(role+'-netns.failed'));syncdir(RUN)
 for name in ('private-runtime','private-genesis'):replace_binary(name,approved)
 systemctl('start',NAME+'host-net.service');systemctl('start',NAME+'net.service')
 host=new_anchor('host');private=new_anchor('private')
 require((host['netns_dev'],host['netns_ino'])==(old_anchors['host']['netns_dev'],old_anchors['host']['netns_ino']),'host namespace changed')
 require((private['netns_dev'],private['netns_ino'])!=(host['netns_dev'],host['netns_ino']),'private namespace equals host')
 require((private['netns_dev'],private['netns_ino'])!=(old_anchors['private']['netns_dev'],old_anchors['private']['netns_ino']),'old private namespace identity reused')
 cfg=json.loads(raw_cfg);cfg['host_namespace_dev']=host['netns_dev'];cfg['host_namespace_ino']=host['netns_ino'];cfg['namespace_dev']=private['netns_dev'];cfg['namespace_ino']=private['netns_ino']
 cfg_bytes=json.dumps(cfg,sort_keys=True,separators=(',',':')).encode()+b'\n'
 newcfg=ETC/'private-runtime.recovery-new';store(newcfg,cfg_bytes,0o644)
 require(read(ETC/'runtime.json',0o644,CONFIG_HASH)[1]==cfg_info,'old config changed before replacement')
 os.replace(newcfg,ETC/'runtime.json');syncdir(ETC)
 require(postgres_id()==SYSTEM_ID,'PG changed before start')
 systemctl('start',NAME+'postgres.service')
 for _ in range(100):
  if (STATE/'socket'/'.s.PGSQL.55432').exists():break
  time.sleep(.1)
 else:raise RuntimeError('PostgreSQL socket unavailable')
 require(not os.path.lexists(STATE/'private-genesis-started') and not os.path.lexists(STATE/'private-genesis-complete'),'genesis already attempted')
 systemctl('start',NAME+'genesis.service')
 require(postgres_id()==SYSTEM_ID,'PG changed after genesis')
 directory(STATE/'pgdata',2004,2004,0o700,PG_INODE);directory(STATE/'socket',2004,2004,0o700,SOCKET_INODE)
 verify_genesis_receipts()
 receipt={'bootstrap_nonce':approved['bootstrap_nonce'],'recovery_nonce':recovery_nonce,'boot_id':cfg['boot_id'],'machine_sha256':approved['machine_sha256'],'postgres_system_id':SYSTEM_ID,'pgdata_dev':PG_INODE[0],'pgdata_ino':PG_INODE[1],'namespace_dev':private['netns_dev'],'namespace_ino':private['netns_ino'],'genesis_sha256':NEW['private-genesis'][1]}
 store(ETC/'private-genesis.json',json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()+b'\n',0o644)
 systemctl('start',NAME+'restate.service');systemctl('start',NAME+'intake.socket');systemctl('start',NAME+'worker.socket');systemctl('start',NAME+'runtime.service')
 # The fixed registration service performs exactly one POST; timeout is unknown.
 systemctl('start',NAME+'register.service')
 new_anchor('host');new_anchor('private')
 store(DONE,b'private canary recovery completed; acceptance tests required\n')
 store(ETC/'private-bootstrap-complete',b'private canary bootstrap completed; acceptance tests required\n',0o644)
 print('private canary recovery completed; production acceptance remains open')

if __name__=='__main__':
 try:
  if sys.argv==[sys.argv[0],'--plan']:print(json.dumps(preflight(),sort_keys=True,indent=2))
  elif sys.argv==[sys.argv[0],'--apply']:
   raw=sys.stdin.buffer.read(1_000_001);require(len(raw)<=1_000_000,'plan too large');apply(json.loads(raw))
  else:raise RuntimeError('expected --plan or --apply')
 except Exception:
  # Once intent exists, stop only exact preverified units, and retain all state.
  if OWNED:
   for suffix in ('intake.socket','worker.socket','runtime.service','register.service','restate.service','postgres.service','net.service','host-net.service'):
    try:systemctl('stop',NAME+suffix)
    except Exception:print('owned stop outcome unresolved: '+NAME+suffix,file=sys.stderr)
  raise
