#!/usr/bin/env python3
"""Review-first, create-only brake frontend installer; never enables a service.

Root PLAN/APPLY requires an exact candidate path, binary digest and plan hash.
Only APPLY generates one independently random key in root memory, writes the two
fixed narrowly permissioned copies, and never logs their contents or digest.
Partial actions are retained for manual review; there is no automatic rollback.
"""
import argparse, grp, hashlib, json, os, pathlib, pwd, stat, subprocess, sys

BASE=pathlib.Path('/usr/local/libexec/software-factory-goose')
ETC=pathlib.Path('/etc/software-factory-goose')
STATE=pathlib.Path('/var/lib/software-factory-goose')
SYSTEM=pathlib.Path('/etc/systemd/system')
SERVER_KEY=ETC/'brake.key'; HUMAN_KEY=ETC/'operator-brake.key'
BIN=BASE/'sfactory_brake_frontend'; SFCTL=BASE/'sfctl'
INTENT=STATE/'brake-frontend-install-intent.json'
RECEIPT=STATE/'brake-frontend-install-receipt.json'
UNITS={
 'software-factory-goose-brake.socket':'''[Unit]
Description=Software Factory operator brake socket
[Socket]
ListenStream=/run/software-factory-goose/brake.sock
SocketUser=root
SocketGroup=bo
SocketMode=0660
DirectoryMode=0755
Accept=no
Service=software-factory-goose-brake.service
RemoveOnStop=yes
[Install]
WantedBy=sockets.target
''',
 'software-factory-goose-brake.service':'''[Unit]
Description=Software Factory nonroot brake frontend
Requires=software-factory-goose-brake.socket
After=software-factory-goose-brake.socket
[Service]
Type=simple
User=sfgoose-brake
Group=sfgoose-brake
ExecStart=/usr/local/libexec/software-factory-goose/sfactory_brake_frontend
NoNewPrivileges=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
UMask=0077
''',
}
TARGETS=(BIN,SFCTL,SERVER_KEY,HUMAN_KEY,*(SYSTEM/name for name in UNITS))

class Refused(Exception):pass

def trusted_dir(path,owner=0,exact=None):
 s=path.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=owner or s.st_mode&0o022 or (exact is not None and stat.S_IMODE(s.st_mode)!=exact):raise Refused('untrusted protected directory')
 out=subprocess.run(['/usr/bin/getfacl','-cp','--',str(path)],check=True,capture_output=True,text=True,timeout=10).stdout
 entries=[x for x in out.splitlines() if x and not x.startswith('#')]
 if len(entries)!=3 or not all(x.startswith(y) for x,y in zip(entries,('user::','group::','other::'))):raise Refused('extended directory ACL')
 return {'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}

def read_candidate(path,expected):
 if (not path.is_absolute() or path.parent.parent!=pathlib.Path('/tmp') or not path.parent.name.startswith('sfactory-') or path.name in ('','.','..') or len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected)):raise Refused('invalid candidate identity')
 parent=trusted_dir(path.parent,owner=1000,exact=0o700)
 pfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  pinned=os.fstat(pfd)
  if (pinned.st_dev,pinned.st_ino,pinned.st_uid,stat.S_IMODE(pinned.st_mode))!=(parent['dev'],parent['ino'],1000,0o700):raise Refused('candidate parent changed')
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=pfd)
 finally:os.close(pfd)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=1000 or s.st_nlink!=1 or s.st_size>64*1024*1024:raise Refused('unsafe candidate')
  data=f.read(64*1024*1024+1)
  if len(data)>64*1024*1024 or hashlib.sha256(data).hexdigest()!=expected:raise Refused('candidate digest mismatch')
  after=os.fstat(f.fileno())
  if (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise Refused('candidate changed')
 return data,{'path':str(path),'sha256':expected,'dev':s.st_dev,'ino':s.st_ino,'size':s.st_size,'parent':parent}

def plan(candidate,expected,sfctl_candidate,sfctl_expected):
 if os.geteuid()!=0:raise Refused('root required')
 parents={str(p):trusted_dir(p) for p in (pathlib.Path('/'),pathlib.Path('/etc'),ETC,pathlib.Path('/etc/systemd'),SYSTEM,pathlib.Path('/var'),pathlib.Path('/var/lib'),STATE,pathlib.Path('/usr'),pathlib.Path('/usr/local'),pathlib.Path('/usr/local/libexec'),BASE)}
 bo=pwd.getpwnam('bo');brake=pwd.getpwnam('sfgoose-brake');group=grp.getgrnam('sfgoose-brake')
 if (bo.pw_uid,bo.pw_gid,brake.pw_uid,brake.pw_gid,group.gr_gid)!=(1000,1000,2003,2003,2003):raise Refused('account identity mismatch')
 if any(p.exists() or p.is_symlink() for p in (*TARGETS,INTENT,RECEIPT)):raise Refused('target exists or previous install incomplete')
 for name in UNITS:
  r=subprocess.run(['/usr/bin/systemctl','show',name,'-p','LoadState','--value'],capture_output=True,text=True,timeout=10,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0'})
  if r.returncode or r.stdout.strip() not in ('','not-found'):raise Refused('systemd unit collision or unavailable')
 binary,source=read_candidate(candidate,expected)
 sfctl,sfctl_source=read_candidate(sfctl_candidate,sfctl_expected)
 spec={'version':1,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'candidate':source,'sfctl_candidate':sfctl_source,'parents':parents,'unit_sha256':{n:hashlib.sha256(s.encode()).hexdigest() for n,s in UNITS.items()},'targets':[str(p) for p in TARGETS],'credentials':'new random 32-byte shared stop key; contents never logged or hashed','activation':'none'}
 return spec,binary,sfctl

def digest(plan_value):return hashlib.sha256(json.dumps(plan_value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def write_new(path,data,mode,uid=0,gid=0):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb') as f:
  os.fchmod(f.fileno(),mode);os.fchown(f.fileno(),uid,gid)
  s=os.fstat(f.fileno())
  if (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)!=(uid,gid,mode,1):raise Refused('created file metadata mismatch')
  f.write(data);f.flush();os.fsync(f.fileno())
 pfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(pfd)
 finally:os.close(pfd)

def apply(spec,binary,sfctl):
 h=digest(spec)
 write_new(INTENT,json.dumps({'plan_sha256':h,'plan':spec},sort_keys=True).encode(),0o600)
 write_new(BIN,binary,0o755)
 write_new(SFCTL,sfctl,0o755)
 for name,value in UNITS.items():write_new(SYSTEM/name,value.encode(),0o644)
 key=bytearray(os.getrandom(32))
 try:
  if len(key)!=32 or not any(key):raise Refused('random source failed')
  write_new(SERVER_KEY,key,0o440,0,2003)
  write_new(HUMAN_KEY,key,0o600,1000,1000)
 finally:
  key[:]=b'\x00'*len(key)
 write_new(RECEIPT,json.dumps({'plan_sha256':h,'status':'installed_not_activated'},sort_keys=True).encode(),0o600)

def main():
 parser=argparse.ArgumentParser();parser.add_argument('operation',choices=('plan','apply'));parser.add_argument('--candidate',required=True,type=pathlib.Path);parser.add_argument('--sha256',required=True);parser.add_argument('--sfctl-candidate',required=True,type=pathlib.Path);parser.add_argument('--sfctl-sha256',required=True);parser.add_argument('--plan-hash')
 args=parser.parse_args();spec,binary,sfctl=plan(args.candidate,args.sha256,args.sfctl_candidate,args.sfctl_sha256);h=digest(spec)
 if args.operation=='plan':print(json.dumps({'plan':spec,'sha256':h},sort_keys=True));return
 if args.plan_hash!=h:raise Refused('exact current plan hash required')
 apply(spec,binary,sfctl);print(json.dumps({'status':'installed_not_activated','plan_sha256':h},sort_keys=True))
if __name__=='__main__':
 try:main()
 except (Refused,OSError,KeyError,ValueError,subprocess.SubprocessError):
  print('REFUSED: brake frontend install unresolved; inspect retained intent',file=sys.stderr);sys.exit(1)
