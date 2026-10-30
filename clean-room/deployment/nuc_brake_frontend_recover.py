#!/usr/bin/env python3
"""Review-first recovery of one partially installed brake credential copy.

No key is printed, hashed, copied to logs or placed in an argument/environment.
A 32-byte equal human copy is read-only evidence; only a confirmed empty exact
inode is writable. Any partial write, change or ambiguity is retained/refused.
"""
import argparse, hashlib, hmac, json, os, pathlib, stat, subprocess, sys

EXPECTED_PLAN='d339e3893031d84dfbf5744bc24facdeaaf8e0c54f3276819874498b247f22e2'
EXPECTED_BINARIES={'/usr/local/libexec/software-factory-goose/sfactory_brake_frontend':'c18388b4e5b1b26cf986bdb893baff8ce6ecc49f229923ff3075ab1bb95af232', '/usr/local/libexec/software-factory-goose/sfctl':'d83b2d93a8cc4b7fddce6c435bafbbdf2b4b2c925d52a713398c4282729f1c6e'}
EXPECTED_UNITS={'software-factory-goose-brake.socket':'9156dd4f32c175f8576a2658234295fa8154bd6d448f1205a667406026bb245a','software-factory-goose-brake.service':'08a835a79442383c893fd0b84eb19a049f1d45d341dec93efb41c880896e1f40'}
ETC=pathlib.Path('/etc/software-factory-goose');STATE=pathlib.Path('/var/lib/software-factory-goose');SYSTEM=pathlib.Path('/etc/systemd/system')
SERVER=ETC/'brake.key'; HUMAN=ETC/'operator-brake.key'
ORIGINAL_INTENT=STATE/'brake-frontend-install-intent.json'; ORIGINAL_RECEIPT=STATE/'brake-frontend-install-receipt.json'
RECOVERY_INTENT=STATE/'brake-frontend-recovery-intent.json'; RECOVERY_RECEIPT=STATE/'brake-frontend-recovery-receipt.json'
SOCKET=pathlib.Path('/run/software-factory-goose/brake.sock')
class Refused(Exception):pass

def acl_fd(fd):
 try:
  out=subprocess.run(['/usr/bin/getfacl','-cp','--',f'/proc/self/fd/{fd}'],pass_fds=(fd,),capture_output=True,text=True,check=True,timeout=10).stdout
 except (OSError,subprocess.SubprocessError):raise Refused('ACL verification unavailable') from None
 entries=[line for line in out.splitlines() if line and not line.startswith('#')]
 if len(entries)!=3 or not all(line.startswith(prefix) for line,prefix in zip(entries,('user::','group::','other::'))):raise Refused('extended ACL refused')

def identity(st):return {'dev':st.st_dev,'ino':st.st_ino,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'size':st.st_size,'nlink':st.st_nlink}

def open_checked(path,uid,gid,mode,size=None,write=False):
 flags=(os.O_RDWR if write else os.O_RDONLY)|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
 fd=os.open(path,flags)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)!=(uid,gid,mode,1) or (size is not None and s.st_size!=size):raise Refused('protected file metadata mismatch')
  acl_fd(fd)
  return fd,identity(s)
 except BaseException:
  os.close(fd);raise

def trusted_dir(path):
 fd=os.open(path,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)&0o022:raise Refused('protected parent mismatch')
  acl_fd(fd)
  return identity(s)
 finally:os.close(fd)

def bounded_public(path,mode,limit):
 fd,meta=open_checked(path,0,0,mode)
 try:
  data=os.read(fd,limit+1)
  if len(data)>limit or len(data)!=meta['size']:raise Refused('protected record size mismatch')
  return data,meta
 finally:os.close(fd)

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def no_path(path):
 try:os.lstat(path)
 except FileNotFoundError:return
 raise Refused('unexpected receipt, socket, or recovery record')
def inactive(name):
 def prop(key):
  r=subprocess.run(['/usr/bin/systemctl','show',name,'-p',key,'--value'],capture_output=True,text=True,timeout=10,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0'})
  if r.returncode:raise Refused('brake unit state unavailable')
  return r.stdout.strip()
 state={key:prop(key) for key in ('LoadState','ActiveState','FragmentPath','DropInPaths','Names')}
 if name.endswith('.service'):state['MainPID']=prop('MainPID')
 if (state['LoadState'] not in ('loaded','not-found') or state['ActiveState']!='inactive'
     or state['DropInPaths'] or state['Names']!=name
     or (name.endswith('.service') and state['MainPID']!='0')):
  raise Refused('brake unit not known inactive')
 expected_path=str(SYSTEM/name) if state['LoadState']=='loaded' else ''
 if state['FragmentPath']!=expected_path:raise Refused('brake unit fragment mismatch')
 return state

def read_key(fd):
 os.lseek(fd,0,os.SEEK_SET)
 data=bytearray(os.read(fd,33))
 if len(data)!=32 or not any(data):
  data[:]=b'\0'*len(data)
  raise Refused('credential unavailable')
 return data

def plan():
 if os.geteuid()!=0:raise Refused('root required')
 parents={str(p):trusted_dir(p) for p in map(pathlib.Path,('/','/etc','/etc/software-factory-goose','/etc/systemd','/etc/systemd/system','/var','/var/lib','/var/lib/software-factory-goose','/usr','/usr/local','/usr/local/libexec','/usr/local/libexec/software-factory-goose','/run'))}
 socket_parent=SOCKET.parent
 try:os.lstat(socket_parent)
 except FileNotFoundError:parents[str(socket_parent)]=None
 else:parents[str(socket_parent)]=trusted_dir(socket_parent)
 for path in (ORIGINAL_RECEIPT,RECOVERY_INTENT,RECOVERY_RECEIPT,SOCKET):no_path(path)
 intent_data,intent_meta=bounded_public(ORIGINAL_INTENT,0o600,256*1024)
 try:intent=json.loads(intent_data)
 except ValueError:raise Refused('original installation intent invalid') from None
 if not isinstance(intent,dict) or not isinstance(intent.get('plan'),dict) or intent.get('plan_sha256')!=EXPECTED_PLAN or digest(intent.get('plan'))!=EXPECTED_PLAN:raise Refused('original plan identity mismatch')
 old_plan=intent['plan']
 if old_plan.get('candidate',{}).get('sha256')!=EXPECTED_BINARIES[next(iter(EXPECTED_BINARIES))] or old_plan.get('sfctl_candidate',{}).get('sha256')!=EXPECTED_BINARIES['/usr/local/libexec/software-factory-goose/sfctl'] or old_plan.get('unit_sha256')!=EXPECTED_UNITS:raise Refused('original plan content mismatch')
 files={};units={}
 for name,want in EXPECTED_BINARIES.items():
  data,meta=bounded_public(pathlib.Path(name),0o755,64*1024*1024)
  if hashlib.sha256(data).hexdigest()!=want:raise Refused('installed binary mismatch')
  files[name]=meta
 for name,want in EXPECTED_UNITS.items():
  data,meta=bounded_public(SYSTEM/name,0o644,32*1024)
  if hashlib.sha256(data).hexdigest()!=want:raise Refused('installed unit mismatch')
  units[name]=inactive(name);files[str(SYSTEM/name)]=meta
 server_fd,server_meta=open_checked(SERVER,0,2003,0o440,32)
 try:
  human_fd,human_meta=open_checked(HUMAN,1000,1000,0o600)
  try:
   if human_meta['size']==0:state='empty'
   elif human_meta['size']==32:
    server=read_key(server_fd)
    try:
     human=read_key(human_fd)
     try:
      if not hmac.compare_digest(server,human):raise Refused('credential copies conflict')
      state='matching_readonly'
     finally:human[:]=b'\0'*len(human)
    finally:server[:]=b'\0'*len(server)
   else:raise Refused('human credential is partial')
  finally:os.close(human_fd)
 finally:os.close(server_fd)
 return {'version':1,'original_plan_sha256':EXPECTED_PLAN,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'parents':parents,'original_intent':intent_meta,'files':files,'unit_states':units,'server_key':server_meta,'human_key':human_meta,'human_state':state,'activation':'none'}

def write_record(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb') as f:
  os.fchmod(f.fileno(),0o600);f.write(json.dumps(value,sort_keys=True).encode());f.flush();os.fsync(f.fileno())
 pfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(pfd)
 finally:os.close(pfd)

def fill_empty(fd,key,expected):
 before=os.fstat(fd)
 if identity(before)!=expected or before.st_size!=0:raise Refused('human credential changed')
 offset=0
 while offset<len(key):
  n=os.write(fd,key[offset:])
  if n<=0:raise Refused('credential copy incomplete')
  offset+=n
 os.fsync(fd)
 after=os.fstat(fd)
 if identity(after)!={**expected,'size':32}:raise Refused('credential copy metadata changed')
 reread=read_key(fd)
 try:
  if not hmac.compare_digest(key,reread):raise Refused('credential copy verification failed')
 finally:reread[:]=b'\0'*len(reread)

def apply(reviewed):
 current=plan()
 if current!=reviewed or current['human_state']!='empty':raise Refused('fresh empty-file recovery plan required')
 h=digest(current);write_record(RECOVERY_INTENT,{'recovery_plan_sha256':h,'plan':current})
 server_fd,server_meta=open_checked(SERVER,0,2003,0o440,32)
 try:
  if server_meta!=current['server_key']:raise Refused('server credential changed')
  key=read_key(server_fd)
  try:
   human_fd,human_meta=open_checked(HUMAN,1000,1000,0o600,0,True)
   try:
    if human_meta!=current['human_key']:raise Refused('human credential changed')
    fill_empty(human_fd,key,current['human_key'])
   finally:os.close(human_fd)
  finally:key[:]=b'\0'*len(key)
 finally:os.close(server_fd)
 write_record(ORIGINAL_RECEIPT,{'plan_sha256':EXPECTED_PLAN,'status':'installed_not_activated','recovered':True})
 write_record(RECOVERY_RECEIPT,{'original_plan_sha256':EXPECTED_PLAN,'recovery_plan_sha256':h,'status':'installed_not_activated'})

def main():
 parser=argparse.ArgumentParser();parser.add_argument('operation',choices=('plan','apply'));parser.add_argument('--plan-hash');args=parser.parse_args()
 current=plan();h=digest(current)
 if args.operation=='plan':print(json.dumps({'plan':current,'sha256':h},sort_keys=True));return
 if args.plan_hash!=h:raise Refused('exact fresh plan required')
 apply(current);print(json.dumps({'status':'installed_not_activated','recovery_plan_sha256':h},sort_keys=True))
if __name__=='__main__':
 try:main()
 except (Refused,OSError,ValueError,KeyError,subprocess.SubprocessError):print('REFUSED: recovery unavailable; retain all existing state',file=sys.stderr);sys.exit(1)
