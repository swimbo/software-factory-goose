#!/usr/bin/env python3
"""Create-only root deadline fixture install; never enables or starts services."""
import hashlib,json,os,pathlib,stat,sys
BASE=pathlib.Path('/usr/local/libexec/software-factory-goose')
ETC=pathlib.Path('/etc/software-factory-goose')
STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
SOURCE=pathlib.Path('/tmp/sfactory-stop-build-_10otcq2/install-candidate/sfactory_deadline_kernel_stop')
TARGET=BASE/'sfactory_deadline_kernel_stop'
GRANTS=ETC/'deadline-grants'
INTENT=STATE/'deadline-install-intent.json'
RECEIPT=STATE/'deadline-install-receipt.json'
SHA='e286a8daab464f29e14e11beed0147cf24a11b585b4dfc50e48cb8615d0a325a'

def directory(p,mode=None):
 s=p.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_mode&0o022 or (mode is not None and stat.S_IMODE(s.st_mode)!=mode):raise RuntimeError('untrusted directory '+str(p))

def source():
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=1000 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o700 or s.st_size>64*1024*1024:raise RuntimeError('candidate identity mismatch')
  data=f.read(64*1024*1024+1)
  if len(data)!=s.st_size or hashlib.sha256(data).hexdigest()!=SHA:raise RuntimeError('candidate digest mismatch')
  return data

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def plan():
 for p in (pathlib.Path('/'),pathlib.Path('/usr'),pathlib.Path('/usr/local'),pathlib.Path('/usr/local/libexec'),BASE,pathlib.Path('/etc'),ETC,pathlib.Path('/var'),pathlib.Path('/var/lib'),STATE.parent):directory(p)
 directory(STATE,0o700)
 if any(os.path.lexists(p) for p in (TARGET,GRANTS,INTENT,RECEIPT)):raise RuntimeError('destination or prior record exists')
 data=source()
 return {'version':1,'purpose':'synthetic-deadline-canary-only','boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'source':str(SOURCE),'binary_sha256':SHA,'targets':[str(TARGET),str(GRANTS)],'service_activation':'none'},data

def sync_dir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)

def write_new(path,data,mode):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 with os.fdopen(fd,'wb') as f:
  os.fchmod(f.fileno(),mode);s=os.fstat(f.fileno())
  if s.st_uid!=0 or s.st_gid!=0:raise RuntimeError('created file owner mismatch')
  f.write(data);f.flush();os.fsync(f.fileno())
 sync_dir(path.parent)

def apply(reviewed):
 if os.geteuid()!=0:raise RuntimeError('root required')
 spec,data=plan()
 if reviewed!=spec:raise RuntimeError('reviewed plan changed')
 h=digest(spec);write_new(INTENT,json.dumps({'plan':spec,'plan_sha256':h},sort_keys=True).encode(),0o600)
 os.mkdir(GRANTS,0o700);os.chmod(GRANTS,0o700);directory(GRANTS,0o700);sync_dir(GRANTS);sync_dir(GRANTS.parent)
 write_new(TARGET,data,0o755)
 write_new(RECEIPT,json.dumps({'plan_sha256':h,'binary_sha256':SHA,'status':'installed_not_activated'},sort_keys=True).encode(),0o600)
 return {'status':'installed_not_activated','plan_sha256':h}

def main():
 if os.geteuid()!=0 or sys.argv!=[sys.argv[0],'plan']:raise RuntimeError('root plan only; apply via source-pinned reviewed bridge')
 print(json.dumps(plan()[0],sort_keys=True))
if __name__=='__main__':main()
