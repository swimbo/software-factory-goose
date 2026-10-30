"""Review-only fixed public-key peer canary. Root PLAN/APPLY; never reads credentials.

Creates and uses only its pinned binary and new unique units. Retains all state on
failure. It tests HTTP authentication only; its fixture backend has no authority.
"""
import hashlib,json,os,pathlib,pwd,grp,stat,subprocess,time
CANDIDATE=pathlib.Path('/tmp/sfactory-public-peer-build.uIuZch65/operator_peer_public_probe')
EXPECTED='a94509cc829b97d5c842f535827ec8d6e77be81a685cf7781e94ff4364310733'
BASE=pathlib.Path('/usr/local/libexec/software-factory-goose'); SYSTEM=pathlib.Path('/etc/systemd/system'); STATE=pathlib.Path('/var/lib/software-factory-goose')
BIN=BASE/'operator-peer-public-probe-7e70f7'; NAME='sfactory-public-peer-7e70f7'; SOCKET=pathlib.Path('/run/software-factory-goose/public-brake-probe.sock')
INTENT=STATE/(NAME+'-intent.json'); RECEIPT=STATE/(NAME+'-receipt.json')
SERVICE=SYSTEM/(NAME+'.service'); SOCKUNIT=SYSTEM/(NAME+'.socket')
UNIT_SERVICE=f'''[Unit]\nDescription=Disposable public peer probe 7e70f7\nRequires={NAME}.socket\nAfter={NAME}.socket\n[Service]\nUser=sfgoose-brake\nGroup=sfgoose-brake\nExecStart={BIN}\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_UNIX\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nRuntimeMaxSec=60s\n'''
UNIT_SOCKET=f'''[Unit]\nDescription=Disposable public peer probe socket 7e70f7\n[Socket]\nListenStream={SOCKET}\nSocketUser=root\nSocketGroup=bo\nSocketMode=0660\nAccept=no\nService={NAME}.service\nRemoveOnStop=yes\n'''
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0'}
def cmd(*args,check=True):
 p=subprocess.run(args,capture_output=True,text=True,timeout=25,env=ENV)
 if len(p.stdout)>16384 or len(p.stderr)>8192 or (check and p.returncode):raise RuntimeError('fixed command failed')
 return p

def protected_dir(p,uid=0):
 fd=os.open(p,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if s.st_uid!=uid or (uid==0 and s.st_gid!=0) or s.st_mode&0o022 or (uid==1000 and (s.st_gid!=1000 or stat.S_IMODE(s.st_mode)!=0o700)):raise RuntimeError('unsafe directory')
  out=subprocess.run(['/usr/bin/getfacl','-cp','--',f'/proc/self/fd/{fd}'],pass_fds=(fd,),capture_output=True,text=True,check=True,timeout=10).stdout
  entries=[x for x in out.splitlines() if x and not x.startswith('#')]
  if len(entries)!=3 or not all(x.startswith(y) for x,y in zip(entries,('user::','group::','other::'))):raise RuntimeError('unsafe ACL')
  return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]
 finally:os.close(fd)

def missing(p):
 try:os.lstat(p)
 except FileNotFoundError:return
 raise RuntimeError('preexisting target')
def unit_absent(name):
 for suffix in ('','d'):
  if suffix:missing(SYSTEM/(name+'.d'))
 r=cmd('/usr/bin/systemctl','show',name,'-p','LoadState','--value')
 if r.stdout.strip() not in ('not-found',''):raise RuntimeError('unit exists')
def candidate():
 fd=os.open(CANDIDATE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))!=(1000,1000,0o700) or s.st_nlink!=1 or s.st_size>64*1024*1024:raise RuntimeError('candidate metadata')
  data=b''
  while len(data)<=s.st_size:
   chunk=os.read(fd,min(1024*1024,s.st_size+1-len(data)))
   if not chunk:break
   data+=chunk
  t=os.fstat(fd)
  if (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)!=(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns) or len(data)!=s.st_size or hashlib.sha256(data).hexdigest()!=EXPECTED:raise RuntimeError('candidate mismatch')
  return data,[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns]
 finally:os.close(fd)
def make_plan(host):
 if os.geteuid()!=0:raise RuntimeError('root required')
 if [(pwd.getpwnam(n).pw_uid,pwd.getpwnam(n).pw_gid) for n in ('bo','sfgoose-brake','sfgoose-worker')]!=[(1000,1000),(2003,2003),(2001,2001)] or grp.getgrnam('bo').gr_gid!=1000:raise RuntimeError('identity mismatch')
 parents={str(p):protected_dir(p) for p in map(pathlib.Path,('/','/usr','/usr/local','/usr/local/libexec',str(BASE),'/etc','/etc/systemd',str(SYSTEM),'/var','/var/lib',str(STATE),'/run','/run/software-factory-goose'))}
 parents[str(CANDIDATE.parent)]=protected_dir(CANDIDATE.parent,1000)
 for p in (BIN,SERVICE,SOCKUNIT,SOCKET,INTENT,RECEIPT):missing(p)
 for name in (NAME+'.service',NAME+'.socket',NAME+'-operator.service',NAME+'-worker.service'):unit_absent(name)
 _,identity=candidate()
 return {'component':'public-operator-peer-probe','source_sha256':host.source_digest,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'candidate_sha256':EXPECTED,'candidate_identity':identity,'parents':parents,'units':{str(SERVICE):hashlib.sha256(UNIT_SERVICE.encode()).hexdigest(),str(SOCKUNIT):hashlib.sha256(UNIT_SOCKET.encode()).hexdigest()},'scope':'public fixed key; side-effect-free backend; new unique units only; daemon-reload; no production credentials or worker activation'}
def write_new(p,data,mode):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 with os.fdopen(fd,'wb') as f:
  os.fchmod(f.fileno(),mode);f.write(data);f.flush();os.fsync(f.fileno());s=os.fstat(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 return [s.st_dev,s.st_ino]
def remove_owned(p,identity):
 s=p.lstat()
 if (s.st_dev,s.st_ino)!=(identity[0],identity[1]) or s.st_uid!=0 or s.st_nlink!=1:raise RuntimeError('cleanup identity changed')
 p.unlink()
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
CLIENT=r'''import socket,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(5);s.connect('/run/software-factory-goose/public-brake-probe.sock')
b=b'{"target":"01ARZ3NDEKTSV4RRFFQ69G5FAV"}'
s.sendall(b'POST /stop HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nx-brake-key: '+b'09'*32+b'\r\nContent-Length: '+str(len(b)).encode()+b'\r\nConnection: close\r\n\r\n'+b)
r=b''
while len(r)<8192:
 x=s.recv(8192-len(r))
 if not x:break
 r+=x
print(r.split(b'\r\n',1)[0].decode())
'''
def peer(role,tag):
 unit=NAME+'-'+tag
 return cmd('/usr/bin/systemd-run','--unit='+unit,'--collect','--wait','--pipe','--quiet','--property=User='+role,'--property=Group=bo','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=RuntimeMaxSec=15s','/usr/bin/python3','-I','-B','-c',CLIENT)
def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('plan changed')
 binary,_=candidate();write_new(INTENT,json.dumps(reviewed,sort_keys=True).encode(),0o600)
 owned={}
 for p,data,mode in ((BIN,binary,0o755),(SERVICE,UNIT_SERVICE.encode(),0o644),(SOCKUNIT,UNIT_SOCKET.encode(),0o644)):owned[p]=write_new(p,data,mode)
 # Any exception retains intent, files and units for exact operator inspection.
 cmd('/usr/bin/systemctl','daemon-reload')
 for name in (NAME+'.service',NAME+'.socket'):
  if (cmd('/usr/bin/systemctl','show',name,'-p','FragmentPath','--value').stdout.strip()!=str(SYSTEM/name) or cmd('/usr/bin/systemctl','show',name,'-p','DropInPaths','--value').stdout.strip() or cmd('/usr/bin/systemctl','show',name,'-p','Names','--value').stdout.strip()!=name):raise RuntimeError('unit fragment mismatch')
 cmd('/usr/bin/systemctl','start',NAME+'.socket')
 good=peer('bo','operator');bad=peer('sfgoose-worker','worker')
 if not good.stdout.strip().startswith('HTTP/1.1 202 ') or not bad.stdout.strip().startswith('HTTP/1.1 403 '):raise RuntimeError('peer result mismatch')
 cmd('/usr/bin/systemctl','stop',NAME+'.socket',NAME+'.service')
 for name in (NAME+'.socket',NAME+'.service'):
  if cmd('/usr/bin/systemctl','is-active',name,check=False).stdout.strip()!='inactive':raise RuntimeError('unit cleanup unresolved')
 missing(SOCKET)
 for p in (SERVICE,SOCKUNIT,BIN):remove_owned(p,owned[p])
 cmd('/usr/bin/systemctl','daemon-reload')
 write_new(RECEIPT,json.dumps({'public_key_valid_operator_status':202,'public_key_valid_wrong_uid_status':403,'units_stopped':True,'fixture_backend_only':True},sort_keys=True).encode(),0o600)
 return {'public_key_valid_operator_status':202,'public_key_valid_wrong_uid_status':403,'production_secret_used':False,'production_acceptance':False}
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest
