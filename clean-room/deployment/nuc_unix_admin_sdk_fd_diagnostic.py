"""One-shot descriptor-class diagnostic of the synthetic SDK Tokio runtime."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_unix_admin_canary_sdk_install as package
SRC=pathlib.Path('/tmp/sfactory-ingress-sdk-20261030/ingress-fd-diagnostic.stripped');SHA='31c96c0526e054280905d9376228f1f627d57ac8a0fee1afc60d0d8cb57343dc'
DIR=base.ROOT/'sdk-preflight';BIN=DIR/'fd-diagnostic';UNIT='sfactory-unix-admin-sdk-fd-diagnostic.service';START=old.ETC/'unix-admin-sdk-fd-diagnostic-started.json';DONE=old.ETC/'unix-admin-sdk-fd-diagnostic-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (BIN,START,DONE)),'diagnostic occupied');old.directory(DIR,0,2000,0o710);old.directory(SRC.parent,1000,1000,0o700)
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=5,check=True).stdout.decode().splitlines();require(paths and len(paths)<=64 and all(pathlib.Path(x).is_absolute() for x in paths),'unit paths unavailable')
 stem=UNIT.removesuffix('.service')
 for parent in map(pathlib.Path,paths):
  for name in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(parent/name),'unit alias occupied')
 for name in (base.NET,base.SERVER):require(active.properties(name).get('ActiveState')=='active','fixture unavailable')
 return {'binary':package.candidate(SRC,SHA,0o755,10000000),'unit':UNIT,'scope':'UID2000 synthetic Tokio FD classes only; no listener or registration'}
def apply(approved):
 require(plan()==approved,'diagnostic plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);require(package.candidate(SRC,SHA,0o755,10000000,BIN)==approved['binary'],'binary changed');old.syncdir(DIR)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--setenv=TOKIO_WORKER_THREADS=2','--property=MemoryMax=128M','--property=TasksMax=32','--property=RuntimeMaxSec=20s',str(BIN)]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'diagnostic outcome unknown');result=json.loads(p.stdout)
 require(isinstance(result,dict) and set(result)<={'eventpoll','eventfd','socket_unix','socket_ipv4','socket_ipv6','socket_other','other'} and all(type(x) is int and 0<=x<=64 for x in result.values()),'diagnostic output unavailable')
 require(old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','diagnostic not terminal')
 output={'classes':result,'listener_started':False,'registration':False};old.store(DONE,base.canonical(output)+b'\n',0o600);return output
