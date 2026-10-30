"""Read-only systemd/Unix peer attestation for the UID2002 coordinator."""
import errno,hashlib,json,os,pathlib,re,socket,stat,subprocess
from nuc_registry_evaluator import EvaluationUnavailable
DIR=pathlib.Path('/usr/local/libexec/software-factory-goose/evaluator-production-v2')
def noacl(fd,directory=False):
 for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr('/proc/self/fd/'+str(fd),name)
  except OSError as e:
   if e.errno==errno.ENODATA:continue
   raise EvaluationUnavailable('ACL unavailable') from None
  raise EvaluationUnavailable('ACL unavailable')
def read(fd,mode,gid,limit):
 st=os.fstat(fd);noacl(fd)
 if not stat.S_ISREG(st.st_mode) or (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))!=(0,gid,1,mode) or st.st_size>limit:raise EvaluationUnavailable('attestation unavailable')
 data=os.read(fd,limit+1)
 if len(data)!=st.st_size:raise EvaluationUnavailable('attestation unavailable')
 return data
def verify(expected_generation):
 if os.getuid()!=2002 or os.geteuid()!=2002 or not isinstance(expected_generation,str) or re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',expected_generation) is None:raise EvaluationUnavailable('identity unavailable')
 attest=DIR/(expected_generation+'.broker-attestation.json');unit_name='sfactoryevalbroker'+expected_generation.lower()+'.service';unit=pathlib.Path('/etc/systemd/system')/unit_name
 parent=os.open(DIR,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(parent);noacl(parent,True)
  if (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(0,2002,0o750):raise EvaluationUnavailable('attestation directory unavailable')
  fd=os.open(attest.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
  try:raw=read(fd,0o440,2002,8192)
  finally:os.close(fd)
 finally:os.close(parent)
 obj=json.loads(raw)
 if not isinstance(obj,dict) or set(obj)!={'schema','boot_id','generation','pid','invocation_id','unit_sha256','socket_dev','socket_ino'} or type(obj['schema']) is not int or obj['schema']!=1 or obj['generation']!=expected_generation or not isinstance(expected_generation,str) or re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',expected_generation) is None or not isinstance(obj['unit_sha256'],str) or re.fullmatch(r'[0-9a-f]{64}',obj['unit_sha256']) is None or not isinstance(obj['invocation_id'],str) or re.fullmatch(r'[0-9a-f]{32}',obj['invocation_id']) is None or type(obj['pid']) is not int or obj['pid']<=1:raise EvaluationUnavailable('attestation unavailable')
 if pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=obj['boot_id']:raise EvaluationUnavailable('boot changed')
 fd=os.open(unit,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:unit=read(fd,0o644,0,65536)
 finally:os.close(fd)
 if hashlib.sha256(unit).hexdigest()!=obj['unit_sha256']:raise EvaluationUnavailable('unit changed')
 parent=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for component in ('run','software-factory-goose','evaluator-production',expected_generation):
   child=os.open(component,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);os.close(parent);parent=child;info=os.fstat(parent);noacl(parent,True)
   if component==expected_generation:
    if (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,2002,0o710):raise EvaluationUnavailable('socket parent unavailable')
   elif info.st_uid!=0 or info.st_mode&0o022:raise EvaluationUnavailable('socket ancestor unavailable')
  st=os.stat('broker.sock',dir_fd=parent,follow_symlinks=False)
  if not stat.S_ISSOCK(st.st_mode) or (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode),st.st_dev,st.st_ino)!=(0,2002,1,0o660,obj['socket_dev'],obj['socket_ino']):raise EvaluationUnavailable('socket changed')
  try:os.getxattr('/proc/self/fd/'+str(parent)+'/broker.sock','system.posix_acl_access',follow_symlinks=False)
  except OSError as e:
   if e.errno!=errno.ENODATA:raise EvaluationUnavailable('socket ACL unavailable') from None
  else:raise EvaluationUnavailable('socket ACL unavailable')
 finally:os.close(parent)
 p=subprocess.run(['/usr/bin/systemctl','show',unit_name,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,InvocationID','--no-pager'],env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C'},capture_output=True,timeout=5,check=False)
 if p.returncode or len(p.stdout)>8192 or len(p.stderr)>8192:raise EvaluationUnavailable('manager unavailable')
 props=dict(line.split('=',1) for line in p.stdout.decode().splitlines())
 if props!={'LoadState':'loaded','ActiveState':'active','MainPID':str(obj['pid']),'Names':unit_name,'FragmentPath':str(unit),'DropInPaths':'','InvocationID':obj['invocation_id']}:raise EvaluationUnavailable('broker changed')
 return hashlib.sha256(raw).hexdigest()
def connect(generation):
 if not isinstance(generation,str) or re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',generation) is None:raise EvaluationUnavailable('generation unavailable')
 path=pathlib.Path('/run/software-factory-goose/evaluator-production')/generation/'broker.sock'
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5)
 try:s.connect(str(path));return s
 except Exception:s.close();raise
