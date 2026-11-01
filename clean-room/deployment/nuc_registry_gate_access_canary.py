"""Disposable native UID/lock canary; no production gate access."""
import fcntl,json,os,pathlib,select,stat,subprocess
import nuc_grant_sidecar_install as old
P=pathlib.Path('/tmp/sfactory-registry-gate-access-20261030')
START=old.ETC/'registry-gate-access-canary-started.json'
DONE=old.ETC/'registry-gate-access-canary-complete.json'
UNITS={'control':'sfactory-registry-gate-access-control-20261030.service','worker':'sfactory-registry-gate-access-worker-20261030.service','blocked':'sfactory-registry-gate-access-blocked-20261030.service'}
def require(v,m):
 if not v: raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(x) for x in (P,START,DONE)),'canary state occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for u in UNITS.values():
  require(old.ctl('show',u,'-p','LoadState','--value')=='not-found','unit occupied')
  stem=u.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
  for base in map(pathlib.Path,paths):
   for p in [base/u,base/(u+'.d'),base/'service.d']+[base/(prefix+'.service.d') for prefix in prefixes]:require(not os.path.lexists(p),'unit alias or drop-in occupied')
 return {'directory':str(P),'units':UNITS,'mode':'root:2000 0710; files root:2000 0440','scope':'native UID 2000/2001 access and shared/exclusive flock; no production gate'}
def command(unit,user,code):
 return ['/usr/bin/systemd-run','--unit='+UNITS[unit],'--wait','--pipe','--quiet','--property=User='+user,'--property=Group='+user,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',code]
def role(unit,user,code):
 p=subprocess.run(command(unit,user,code),env=old.ENV,capture_output=True,timeout=30,check=False)
 require(p.returncode==0 and len(p.stdout)<4096 and len(p.stderr)<4096,'native role failure')
 return json.loads(p.stdout)
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 os.mkdir(P,0o700);os.chown(P,0,2000);os.chmod(P,0o710)
 for name,data in [('gate.lock',b''),('head.json',b'{}\n')]:
  fd=os.open(P/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:os.fchown(fd,0,2000);os.fchmod(fd,0o440);os.write(fd,data);os.fsync(fd)
  finally:os.close(fd)
 old.syncdir(P)
 identities={str(p):(os.lstat(p).st_dev,os.lstat(p).st_ino) for p in (P.parent,P,P/'gate.lock',P/'head.json')}
 common='''import os,stat,fcntl,json,time\np=%r\ns=open('/proc/self/status').read();assert 'NoNewPrivs:\\t1' in s and all(('Cap'+n+':\\t0000000000000000') in s for n in ('Inh','Prm','Eff','Bnd','Amb'))\n'''%str(P)
 control=common+'''assert (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2000,2000,2000,2000)\nd=os.open(p,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW);st=os.fstat(d);assert (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(0,2000,0o710)\nf=os.open('gate.lock',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=d);h=os.open('head.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=d);assert os.read(h,16)==b'{}\\n'\nfor fn in (lambda:os.open('gate.lock',os.O_WRONLY,dir_fd=d),lambda:os.open('new',os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600,dir_fd=d),lambda:os.unlink('head.json',dir_fd=d)):\n try:fn()\n except PermissionError:continue\n raise RuntimeError('mutation allowed')\nfcntl.flock(f,fcntl.LOCK_SH);print(json.dumps({'ready':True}),flush=True);time.sleep(6)\n'''
 worker=common+'''assert (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2001,2001,2001,2001)\nd=os.open(p,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW)\nfor fn in (lambda:os.open('gate.lock',os.O_RDONLY,dir_fd=d),lambda:os.open('head.json',os.O_RDONLY,dir_fd=d),lambda:os.open('new',os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600,dir_fd=d)):\n try:fn()\n except PermissionError:continue\n raise RuntimeError('worker access allowed')\nprint(json.dumps({'denied':True}))\n'''
 blocked=common+'''assert (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2000,2000,2000,2000)\nf=os.open(os.path.join(p,'gate.lock'),os.O_RDONLY|os.O_NOFOLLOW)\ntry:fcntl.flock(f,fcntl.LOCK_SH|fcntl.LOCK_NB)\nexcept BlockingIOError:print(json.dumps({'blocked':True}));raise SystemExit(0)\nraise RuntimeError('shared lock allowed')\n'''
 proc=subprocess.Popen(command('control','sfgoose-control',control),env=old.ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 ready,_,_=select.select([proc.stdout],[],[],15);require(bool(ready) and json.loads(proc.stdout.readline())=={'ready':True},'holder readiness unknown')
 fd=os.open(P/'gate.lock',os.O_RDONLY|os.O_NOFOLLOW)
 try:
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);raise RuntimeError('exclusive lock allowed')
  except BlockingIOError:pass
  out,err=proc.communicate(timeout=15);require(proc.returncode==0 and len(out)<4096 and len(err)<4096,'holder failed')
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  require(role('blocked','sfgoose-control',blocked)=={'blocked':True},'shared lock not blocked')
 finally:os.close(fd)
 require(role('worker','sfgoose-worker',worker)=={'denied':True},'worker access')
 for unit in UNITS.values():
  require(old.ctl('show',unit,'-p','ActiveState','--value') in ('inactive','failed') and old.ctl('show',unit,'-p','MainPID','--value')=='0' and old.ctl('show',unit,'-p','Job','--value')=='','unit not terminal')
 for path,identity in identities.items():
  st=os.lstat(path);require((st.st_dev,st.st_ino)==identity,'fixture inode changed')
 for name in ('gate.lock','head.json'):
  st=os.lstat(P/name);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink)==(0,2000,0o440,1),'fixture changed');os.unlink(P/name)
 require(not list(P.iterdir()),'unexpected fixture entries');os.rmdir(P);old.syncdir(P.parent)
 result={'uid2000_read_shared_and_mutation_denied':True,'uid2001_denied':True,'exclusive_and_shared_contention':True,'capabilities_empty_nnp':True}
 old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
