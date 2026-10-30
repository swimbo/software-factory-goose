#!/usr/bin/env python3
"""Create-only resource drop-ins for the stopped failed private canary.

PLAN/APPLY, no start or database mutation. A partial apply is retained for
manual reconciliation, never replayed automatically.
"""
import errno,hashlib,json,os,pathlib,re,stat,subprocess,sys
ROOT=pathlib.Path('/etc/software-factory-goose')
UNIT=pathlib.Path('/etc/systemd/system')
PREFIX='software-factory-goose-private-'
UNIT_SHA={
 'host-net.service':'86facd848497e5d32376ddbc0c494aa493445739728787a88f799971d39e38e3',
 'net.service':'cc52bf8108541f2b8b57ab2c2c8eb150ec803127d06d6dda6dc93de1252f5727',
 'initdb.service':'4f599b07444e2960e3bc267f2f8cb975549c09b575b85aaee2e85966a554d1fb',
 'postgres.service':'f0bd0aa9150215fc43d05c124c36160a1e7559c919731e4818f59e67d77bcfa6',
 'createdb.service':'fb64be189c72fa3207c192a6c7dc86af1f599839e0ced6378e5c2e60310d478a',
 'genesis.service':'5e6a38dc54f47e85fe6d5e3861fbc893081cc83cb868d80342bcb5ea9b737493',
 'restate.service':'29d77496a0d3c3b67fc7c5a31b16654fd86dcec1505273ce70919f594756a8ae',
 'intake.socket':'6a163dc05e354118272cc04671282a7a0c31cf72f7a0f2243edda5b180928088',
 'worker.socket':'e7c08c196e30c821bc714923b89b3d21dad8fea68602733f19b8c0310ccd1cc5',
 'runtime.service':'5fe9af9180d08242e40614a5b1994ea3b4933bc92694b28abf8d48fcc69e3ebe',
 'register.service':'20c04a7460a6b3851ffa9906bbb136639c76b636594346f17f22e3621b158249',
}
LIMITS={'host-net.service':('64M',16,'50%'),'net.service':('64M',16,'50%'),
 'initdb.service':('1G',64,'100%'),'postgres.service':('1G',128,'200%'),
 'createdb.service':('64M',16,'50%'),'genesis.service':('512M',64,'100%'),
 'restate.service':('4G',256,'200%'),'runtime.service':('512M',128,'100%'),
 'register.service':('64M',16,'50%')}
INTENT=ROOT/'private-resource-limits-started.json';DONE=ROOT/'private-resource-limits-complete.json'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LANG':'C'}

def require(ok,message):
 if not ok:raise RuntimeError(message)
def directory(path,mode):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode,'unsafe ancestor')
  for attr in ('system.posix_acl_access','system.posix_acl_default'):
   try:os.getxattr(fd,attr)
   except OSError as e:require(e.errno==errno.ENODATA,'ACL unknown')
   else:raise RuntimeError('ACL forbidden')
 finally:os.close(fd)
def unit_hash(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o644 and s.st_size<=16384,'unsafe unit')
  try:os.getxattr(fd,'system.posix_acl_access')
  except OSError as e:require(e.errno==errno.ENODATA,'unit ACL unknown')
  else:raise RuntimeError('unit ACL forbidden')
  content=os.read(fd,16385);require(len(content)==s.st_size,'unit changed')
  return hashlib.sha256(content).hexdigest()
 finally:os.close(fd)
def state(name):
 p=subprocess.run(['/usr/bin/systemctl','show',PREFIX+name,'--property=ActiveState','--value'],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
 require(len(p.stdout)<=64,'unit state unavailable');return p.stdout.decode().strip()
def dropin(name):
 memory,tasks,cpu=LIMITS[name]
 return f'[Service]\nMemoryMax={memory}\nTasksMax={tasks}\nCPUQuota={cpu}\n'.encode()
def store(path,data,mode):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 try:
  os.fchmod(fd,mode);view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def plan():
 require(os.geteuid()==0,'root required')
 for path,mode in [(pathlib.Path('/'),0o755),(pathlib.Path('/etc'),0o755),(pathlib.Path('/etc/systemd'),0o755),(UNIT,0o755),(ROOT,0o711)]:directory(path,mode)
 require(not os.path.lexists(INTENT) and not os.path.lexists(DONE),'resource attempt already exists')
 observations={}
 for name,digest in UNIT_SHA.items():
  path=UNIT/(PREFIX+name);require(unit_hash(path)==digest,'unit source differs')
  require(not os.path.lexists(UNIT/(PREFIX+name+'.d')),'drop-in directory occupied')
  active=state(name);require(active in ('inactive','failed'),'unit not stopped')
  st=os.lstat(path);observations[name]={'dev':st.st_dev,'ino':st.st_ino,'sha256':digest,'state':active,'dropin_sha256':hashlib.sha256(dropin(name)).hexdigest() if name in LIMITS else None}
 return {'format':1,'machine_sha256':hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes().strip()).hexdigest(),'units':observations}
def loaded_properties(name):
 p=subprocess.run(['/usr/bin/systemctl','show',PREFIX+name,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec','--no-pager'],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
 require(len(p.stdout)<=8192 and len(p.stderr)<=8192,'loaded unit properties unavailable')
 pairs={}
 for line in p.stdout.decode().splitlines():
  key,separator,value=line.partition('=');require(separator and key not in pairs,'invalid loaded properties');pairs[key]=value
 return pairs

def cpu_usec(value):
 match=re.fullmatch(r'([0-9]+)(us|ms|s|min|h)',value)
 require(match is not None,'unknown CPU quota rendering')
 return int(match.group(1))*{'us':1,'ms':1000,'s':1000000,'min':60000000,'h':3600000000}[match.group(2)]

def verify_loaded():
 for name in UNIT_SHA:
  data=loaded_properties(name)
  require(data.get('LoadState')=='loaded' and data.get('ActiveState') in ('inactive','failed') and data.get('FragmentPath')==str(UNIT/(PREFIX+name)) and data.get('Names')==PREFIX+name,'loaded unit identity/state mismatch')
  if name not in LIMITS:
   require(data.get('DropInPaths','')=='','unexpected socket drop-in')
   continue
  memory,tasks,cpu=LIMITS[name]
  factor={'M':1024**2,'G':1024**3}[memory[-1]];memory_bytes=int(memory[:-1])*factor
  expected_cpu=int(cpu[:-1])*10000
  require(data.get('MainPID')=='0' and data.get('DropInPaths')==str(UNIT/(PREFIX+name+'.d')/'50-resources.conf'),'loaded unit process/drop-in mismatch')
  require(data.get('MemoryMax')==str(memory_bytes) and data.get('TasksMax')==str(tasks) and cpu_usec(data.get('CPUQuotaPerSecUSec',''))==expected_cpu,'loaded resource limit mismatch')


def apply(approved):
 require(plan()==approved,'reviewed plan changed')
 store(INTENT,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 for name in LIMITS:
  path=UNIT/(PREFIX+name+'.d');os.mkdir(path,0o755);os.chmod(path,0o755)
  fd=os.open(UNIT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
  store(path/'50-resources.conf',dropin(name),0o644)
 p=subprocess.run(['/usr/bin/systemctl','daemon-reload'],env=ENV,capture_output=True,timeout=30,check=False)
 require(p.returncode==0,'daemon reload uncertain; retain partial state')
 verify_loaded()
 store(DONE,b'resource drop-ins installed; no units started\n',0o600)
 print('resource drop-ins installed; no units started')
if __name__=='__main__':
 if sys.argv==[sys.argv[0],'--plan']:print(json.dumps(plan(),sort_keys=True,indent=2))
 elif sys.argv==[sys.argv[0],'--apply']:
  raw=sys.stdin.buffer.read(1_000_001);require(len(raw)<=1_000_000,'plan too large');apply(json.loads(raw))
 else:raise SystemExit('expected --plan or --apply')
