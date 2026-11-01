"""One-shot native cap-zero PIDFD kill of one task-owned idle systemd unit."""
import hashlib,json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
ROOT=old.ETC;TARGET='sfactory-eval-pidfd-owned-target.service';KILLER='sfactory-eval-pidfd-owned-killer.service';START=ROOT/'eval-pidfd-kill-started.json';BOUND=ROOT/'eval-pidfd-kill-target.json';DONE=ROOT/'eval-pidfd-kill-complete.json';SCRIPT=ROOT/'eval-pidfd-kill-program.py'
CODE="""import json,os,pathlib,signal,subprocess
f=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
if os.geteuid()!=0 or f.get('NoNewPrivs','').strip()!='1' or any(int(f[k].strip(),16) for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise RuntimeError('privileges unavailable')
p='/etc/software-factory-goose/eval-pidfd-kill-target.json'
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:r=json.loads(os.read(fd,8193))
finally:os.close(fd)
if set(r)!={'pid','invocation','boot_id'} or pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=r['boot_id']:raise RuntimeError('target unavailable')
env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C'}
def props():
 p=subprocess.run(['/usr/bin/systemctl','show','sfactory-eval-pidfd-owned-target.service','-p','MainPID','-p','InvocationID','-p','ActiveState','--no-pager'],env=env,capture_output=True,timeout=5,check=True)
 return dict(x.split('=',1) for x in p.stdout.decode().splitlines())
fd=os.pidfd_open(r['pid'],0)
try:
 q=props()
 if q!={'MainPID':str(r['pid']),'InvocationID':r['invocation'],'ActiveState':'active'}:raise RuntimeError('target changed')
 signal.pidfd_send_signal(fd,signal.SIGKILL)
finally:os.close(fd)
print('PASS native pidfd kill',flush=True)
"""
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,BOUND,DONE,SCRIPT)),'scope occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','--system','unit-paths'],env=old.ENV,capture_output=True,timeout=5,check=True).stdout.decode().splitlines()
 require(paths and len(paths)<=64 and all(pathlib.Path(p).is_absolute() for p in paths),'unit search paths unavailable')
 for unit in (TARGET,KILLER):
  require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','unit occupied')
  for parent in paths:
   for name in [unit,unit+'.d','service.d']+[unit[:i+1]+'service.d' for i,c in enumerate(unit[:-8]) if c=='-']:
    require(not os.path.lexists(pathlib.Path(parent)/name),'unit alias occupied')
 return {'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'target':TARGET,'killer':KILLER,'code_sha256':hashlib.sha256(CODE.encode()).hexdigest(),'scope':'owned idle target only; no provider'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600);old.store(SCRIPT,CODE.encode(),0o600)
 base=['/usr/bin/systemd-run','--quiet','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=PrivateNetwork=yes','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=60s']
 subprocess.run(base+['--unit='+TARGET,'/usr/bin/sleep','60'],env=old.ENV,capture_output=True,timeout=15,check=True)
 pid=int(old.ctl('show',TARGET,'-p','MainPID','--value'));inv=old.ctl('show',TARGET,'-p','InvocationID','--value')
 require(pid>1 and re.fullmatch(r'[0-9a-f]{32}',inv) is not None and old.ctl('show',TARGET,'-p','ActiveState','--value')=='active','target unknown')
 old.store(BOUND,json.dumps({'pid':pid,'invocation':inv,'boot_id':approved['boot_id']},sort_keys=True).encode()+b'\n',0o600)
 p=subprocess.run(base+['--wait','--pipe','--unit='+KILLER,'/usr/bin/python3','-I','-B',str(SCRIPT)],env=old.ENV,capture_output=True,timeout=30,check=False)
 require(p.returncode==0 and p.stdout==b'PASS native pidfd kill\n' and len(p.stderr)<=4096,'killer outcome unknown')
 require(old.ctl('show',TARGET,'-p','MainPID','--value')=='0' and old.ctl('show',TARGET,'-p','Job','--value')=='' and old.ctl('show',TARGET,'-p','Result','--value')=='signal','target outcome unknown')
 require(old.ctl('show',KILLER,'-p','MainPID','--value')=='0' and old.ctl('show',KILLER,'-p','Job','--value')=='','killer outcome unknown')
 result={'target':TARGET,'pid':pid,'native_capabilities_empty':True,'pidfd_sigkill':True,'result':'signal','provider_called':False};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
