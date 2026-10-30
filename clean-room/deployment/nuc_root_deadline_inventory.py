"""Fixed read-only inventory of owned synthetic native deadline canaries."""
import hashlib,json,os,pathlib,re,stat,subprocess
STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
ROOT=pathlib.Path('/etc/software-factory-goose/tasks')
GRANTS=pathlib.Path('/etc/software-factory-goose/deadline-grants')
CGROUP=pathlib.Path('/sys/fs/cgroup')
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0','LC_ALL':'C'}
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def read(path,optional=False):
 try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 except FileNotFoundError:
  if optional:return None
  raise
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>16384:raise RuntimeError('untrusted record: '+str(path))
  raw=f.read(16385)
  if len(raw)!=s.st_size or f.read(1):raise RuntimeError('record changed: '+str(path))
 return {'sha256':hashlib.sha256(raw).hexdigest(),'value':json.loads(raw)}

def unit(name):
 p=subprocess.run(['/usr/bin/systemctl','show',name,'--property=LoadState,ActiveState,SubState,Job,Names,FragmentPath,DropInPaths,Transient,Result','--no-pager'],capture_output=True,text=True,timeout=10,env=ENV)
 if p.returncode or len(p.stdout)>16384:raise RuntimeError('unit state unavailable')
 values={}
 for line in p.stdout.splitlines():
  k,sep,v=line.partition('=')
  if not sep or k in values:raise RuntimeError('ambiguous unit properties')
  values[k]=v
 return values

def make_plan(host):
 if os.geteuid()!=0:raise RuntimeError('root required')
 rows=[];entries=list(STATE.glob('*.deadline-canary-intent.json'))
 if len(entries)>1000:raise RuntimeError('too many fixture records')
 for p in sorted(entries):
  intent=read(p);v=intent['value'];target=v.get('target','')
  if v.get('purpose')!='native-deadline-sleeper':continue
  if not re.fullmatch('[0-7][0-9A-HJKMNP-TV-Z]{25}',target) or p.name!=target+'.deadline-canary-intent.json':raise RuntimeError('target mismatch')
  sl='sfactory'+target.lower()+'.slice';anchor='sfactory'+target.lower()+'-deadline-anchor.service';base='sfactorydeadline'+target.lower();timer=base+'.timer';service=base+'.service'
  if v.get('slice')!=sl or v.get('unit')!=anchor:raise RuntimeError('intent unit mismatch')
  cat=read(ROOT/(target+'.json'),True);grant=read(GRANTS/(target+'.json'),True);armed=read(STATE/(target+'.deadline-armed.json'),True)
  arm_intent=read(STATE/(target+'.deadline-intent.json'),True);observation=read(STATE/(target+'.observation'),True);receipt=read(STATE/(target+'.deadline-canary-receipt.json'),True)
  try:
   fd=os.open(STATE/(target+'.closed'),os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
  except FileNotFoundError:closed=None
  else:
   with os.fdopen(fd,'rb') as f:
    s=os.fstat(f.fileno());raw=f.read(129)
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or raw!=(target+'\n').encode():raise RuntimeError('bad closure')
   closed={'sha256':hashlib.sha256(raw).hexdigest(),'valid':True}
  try:
   st=(CGROUP/sl).lstat();cgroup={'exists':True,'dev':st.st_dev,'ino':st.st_ino}
  except FileNotFoundError:cgroup={'exists':False}
  rows.append({'target':target,'intent':intent,'catalog':cat,'grant':grant,'arm_intent':arm_intent,'armed':armed,'observation':observation,'closed':closed,'receipt':receipt,'cgroup':cgroup,'units':{n:unit(n) for n in (anchor,sl,timer,service)}})
 return {'component':'root-deadline-inventory','source_sha256':host.source_digest,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'records':rows}
