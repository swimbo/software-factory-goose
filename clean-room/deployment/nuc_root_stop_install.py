#!/usr/bin/env python3
"""Review-first, create-only installer for root stop backend; never activates it.

PLAN is read-only. APPLY requires the exact PLAN hash and retains all partial
state on error; it does not reload systemd or start/enable a unit.
"""
import grp,hashlib,json,os,pathlib,pwd,stat,subprocess,sys

BASE=pathlib.Path('/usr/local/libexec/software-factory-goose')
ETC=pathlib.Path('/etc/software-factory-goose')
STATE=pathlib.Path('/var/lib/software-factory-goose')
SYSTEM=pathlib.Path('/etc/systemd/system')
SRC=pathlib.Path('/tmp/sfactory-stop-build-_10otcq2/install-candidate/sfactory_root_stop')
EXPECTED='4369a4712c2563ef8516b19053c2821a7246c928516ca3d03e9a2530e00348f1'
UNITS={'software-factory-goose-root-stop.service': '# REVIEW DRAFT: cgroup writes remain privileged; inspect catalogue and peer code.\n[Unit]\nDescription=Software Factory root stop-only authority\nRequires=software-factory-goose-root-stop.socket\nAfter=software-factory-goose-root-stop.socket\n[Service]\nType=simple\nUser=root\nGroup=root\nExecStart=/usr/local/libexec/software-factory-goose/sfactory_root_stop\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_UNIX\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=/var/lib/software-factory-goose/stop /sys/fs/cgroup\nUMask=0077\n', 'software-factory-goose-root-stop.socket': '# REVIEW DRAFT: do not install or enable before privileged canaries.\n[Unit]\nDescription=Software Factory root stop socket\n[Socket]\nListenStream=/run/software-factory-goose/root-stop.sock\nSocketUser=root\nSocketGroup=sfgoose-brake\nSocketMode=0660\nDirectoryMode=0755\nAccept=no\nService=software-factory-goose-root-stop.service\nRemoveOnStop=yes\n[Install]\nWantedBy=sockets.target\n'}
TARGETS=(ETC/'tasks',STATE/'stop',BASE/'sfactory_root_stop',SYSTEM/'software-factory-goose-root-stop.service',SYSTEM/'software-factory-goose-root-stop.socket')
INTENT=STATE/'root-stop-install-intent.json'; RECEIPT=STATE/'root-stop-install-receipt.json'

def trusted_dir(path,mode=None):
 st=path.lstat()
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_mode&0o022 or (mode is not None and stat.S_IMODE(st.st_mode)!=mode):raise RuntimeError('untrusted directory: '+str(path))

def read_binary():
 # The source belongs to the already authorized host administrator; the fixed
 # digest, no-follow descriptor and metadata pin the bytes used for this apply.
 fd=os.open(SRC,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=1000 or s.st_nlink!=1 or s.st_size>64*1024*1024:raise RuntimeError('source binary unavailable')
  data=f.read(64*1024*1024+1)
 if hashlib.sha256(data).hexdigest()!=EXPECTED:raise RuntimeError('source digest mismatch')
 return data

def plan():
 for p in (pathlib.Path('/'),pathlib.Path('/etc'),ETC,pathlib.Path('/etc/systemd'),SYSTEM,pathlib.Path('/var'),pathlib.Path('/var/lib'),STATE,pathlib.Path('/usr'),pathlib.Path('/usr/local'),pathlib.Path('/usr/local/libexec'),BASE):trusted_dir(p)
 role=pwd.getpwnam('sfgoose-brake');group=grp.getgrnam('sfgoose-brake')
 if role.pw_uid!=2003 or role.pw_gid!=2003 or group.gr_gid!=2003:raise RuntimeError('brake identity mismatch')
 for name in UNITS:
  p=subprocess.run(['/usr/bin/systemctl','show',name,'-p','LoadState','--value'],capture_output=True,text=True,timeout=10,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0'})
  if p.returncode!=0 or p.stdout.strip() not in ('','not-found'):raise RuntimeError('manager unit collision or unavailable')
 if any(p.exists() or p.is_symlink() for p in (*TARGETS,INTENT,RECEIPT)):raise RuntimeError('target or prior installation record exists; retain for review')
 source=read_binary()
 return {'version':1,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'binary_sha256':hashlib.sha256(source).hexdigest(),'units':{name:hashlib.sha256(value.encode()).hexdigest() for name,value in UNITS.items()},'targets':[str(x) for x in TARGETS],'activation':'none'},source

def digest(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def write_new(path,data,mode):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 with os.fdopen(fd,'wb') as f:
  os.fchmod(f.fileno(),mode);st=os.fstat(f.fileno())
  if st.st_uid!=0 or st.st_gid!=0:raise RuntimeError('created file owner mismatch')
  f.write(data);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)

def main():
 if len(sys.argv) not in (2,3) or sys.argv[1] not in ('plan','apply'):raise RuntimeError('expected plan or apply PLAN_HASH')
 spec,binary=plan(); h=digest(spec)
 if sys.argv[1]=='plan':print(json.dumps({'plan':spec,'sha256':h},sort_keys=True));return
 if len(sys.argv)!=3 or sys.argv[2]!=h or os.geteuid()!=0:raise RuntimeError('root and exact current plan required')
 write_new(INTENT,json.dumps({'plan_sha256':h,'plan':spec},sort_keys=True).encode(),0o600)
 for directory in (ETC/'tasks',STATE/'stop'):
  os.mkdir(directory,0o700);os.chmod(directory,0o700)
  fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
  fd=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 write_new(BASE/'sfactory_root_stop',binary,0o755)
 for name,text in UNITS.items():write_new(SYSTEM/name,text.encode(),0o644)
 write_new(RECEIPT,json.dumps({'plan_sha256':h,'status':'installed_not_activated'},sort_keys=True).encode(),0o600)
 print(json.dumps({'status':'installed_not_activated','plan_sha256':h},sort_keys=True))
if __name__=='__main__':main()
