"""Synthetic broker PID signal-zero diagnostic; no terminating signal."""
import json,os,pathlib,signal,subprocess
import nuc_grant_sidecar_install as old
NAME='sfactory-eval-canary3-pidfd-diagnostic.service';PID=1
INTENT=old.ETC/'evaluator-canary3-pidfd-diagnostic-started.json';DONE=old.ETC/'evaluator-canary3-pidfd-diagnostic-complete.json'
CODE="""import json,os,signal
f=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
if os.geteuid()!=0 or f.get('NoNewPrivs','').strip()!='1' or any(int(f[k].strip(),16) for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise RuntimeError('identity')
fd=os.pidfd_open(1,0)
try:
 try:signal.pidfd_send_signal(fd,0);out=0
 except OSError as e:out=e.errno
 print(json.dumps({'errno':out,'seccomp':int(f['Seccomp'].strip())}),flush=True)
finally:os.close(fd)
"""
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (INTENT,DONE)),'diagnostic occupied')
 require(pathlib.Path('/proc/1/status').is_file(),'PID1 unavailable')
 require(old.ctl('show',NAME,'-p','LoadState','--value')=='not-found','diagnostic unit occupied')
 for parent in ('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system'):
  for name in [NAME,NAME+'.d','service.d']+[NAME[:i+1]+'service.d' for i,c in enumerate(NAME[:-8]) if c=='-']:
   require(not os.path.lexists(pathlib.Path(parent)/name),'unit alias occupied')
 return {'target_pid':PID,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'unit':NAME,'scope':'PID1 signal zero only; no stop or provider'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(INTENT,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 fd=os.pidfd_open(PID,0)
 try:
  try:signal.pidfd_send_signal(fd,0);bridge_errno=0
  except OSError as e:bridge_errno=e.errno
 finally:os.close(fd)
 args=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--unit='+NAME,'--property=User=root','--property=Group=root','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=NoNewPrivileges=yes','--property=PrivateNetwork=yes','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',CODE]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=30,check=False)
 require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'native diagnostic unknown')
 native=json.loads(p.stdout);require(set(native)=={'errno','seccomp'} and type(native['errno']) is int and type(native['seccomp']) is int,'native output unavailable')
 require(old.ctl('show',NAME,'-p','MainPID','--value')=='0' and old.ctl('show',NAME,'-p','Job','--value')=='','native termination unavailable')
 fields=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
 result={'bridge_seccomp':int(fields['Seccomp'].strip()),'bridge_errno':bridge_errno,'native_errno':native['errno'],'native_seccomp':native['seccomp'],'signal':0,'no_process_stopped':True};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
