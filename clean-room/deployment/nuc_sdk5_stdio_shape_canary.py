"""Observe PID1 --pipe stdin shapes in two fresh root cap-empty units."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_offline_backup as backup
START=old.ETC/'sdk5-stdio-shape-started.json';DONE=old.ETC/'sdk5-stdio-shape-complete.json'
UNITS=('sfactory-sdk5-stdio-shape-inherited.service','sfactory-sdk5-stdio-shape-null.service')
CODE="""import ctypes,fcntl,json,os,stat
if ctypes.CDLL(None).prctl(4,0,0,0,0)!=0: raise RuntimeError('dump protection unavailable')
status=dict(x.split(':',1) for x in open('/proc/self/status') if ':' in x)
if not (os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0 and status['NoNewPrivs'].strip()=='1' and all(int(status['Cap'+k],16)==0 for k in ('Inh','Prm','Eff','Bnd','Amb'))): raise RuntimeError('identity unavailable')
a=os.fstat(0);n=os.stat('/dev/null');flags=fcntl.fcntl(0,fcntl.F_GETFL)
print(json.dumps({'fifo':stat.S_ISFIFO(a.st_mode),'character':stat.S_ISCHR(a.st_mode),'same_device_inode':(a.st_dev,a.st_ino)==(n.st_dev,n.st_ino),'same_rdev':a.st_rdev==n.st_rdev,'readonly':flags&os.O_ACCMODE==os.O_RDONLY},sort_keys=True))
"""
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'stdio fixture occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for unit in UNITS:
  require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','stdio unit occupied');stem=unit.removesuffix('.service')
  for root in map(pathlib.Path,paths):
   for n in [unit,unit+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/n),'stdio unit collision')
 return {'schema':1,'units':list(UNITS),'code_sha256':backup.sha(CODE.encode()),'scope':'root cap-zero stdio shape only; no production access'}
def apply(approved):
 require(plan()==approved,'stdio plan changed');old.store(START,backup.canonical(approved),0o600);out=[]
 for unit,stdin in zip(UNITS,(None,subprocess.DEVNULL)):
  args=['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--quiet','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=StandardInput=null','--property=MemoryMax=32M','--property=TasksMax=8','--property=RuntimeMaxSec=10s','/usr/bin/python3','-I','-B','-c',CODE]
  p=subprocess.run(args,stdin=stdin,env=old.ENV,capture_output=True,timeout=20,check=False);require(p.returncode==0 and len(p.stdout)<=1024 and len(p.stderr)<=1024,'stdio observation unknown');v=json.loads(p.stdout);require(set(v)=={'fifo','character','same_device_inode','same_rdev','readonly'} and all(type(x) is bool for x in v.values()) and old.ctl('show',unit,'-p','MainPID','--value')=='0' and old.ctl('show',unit,'-p','Job','--value')=='','stdio result unavailable');out.append(v)
 result={'schema':1,'inherited':out[0],'devnull':out[1],'production_access':False};old.store(DONE,backup.canonical(result),0o600);return result
