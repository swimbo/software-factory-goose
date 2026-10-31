"""One fixed UID2000 HTTP/2 discovery request to the owned synthetic SDK."""
import json,os,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_probe_start as probe
NAME='sfactory-unix-admin-h2-contrast.service'
START=old.ETC/'unix-admin-canary-h2-contrast-started.json'
DONE=old.ETC/'unix-admin-canary-h2-contrast-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE),'contrast already attempted')
 epoch=probe.epoch()
 require(old.ctl('show',NAME,'-p','LoadState','--value')=='not-found','unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines()
 stem=NAME.removesuffix('.service'); prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
 import pathlib
 for root in map(pathlib.Path,paths):
  for path in [root/NAME,root/(NAME+'.d'),root/'service.d']+[root/(p+'.service.d') for p in prefixes]:require(not os.path.lexists(path),'unit collision')
 return {'schema':1,'epoch_sha256':epoch,'unit':NAME,'scope':'one fixed HTTP/2 discovery GET, no invocation'}
def apply(approved):
 require(plan()==approved,'contrast plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 argv=['/usr/bin/systemd-run','--unit='+NAME,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=15s','/usr/bin/curl','--disable','--silent','--show-error','--fail','--max-time','5','--max-filesize','65536','--http2-prior-knowledge','--noproxy','*','-H','Accept: application/vnd.restate.endpointmanifest.v4+json','http://127.0.0.1:9081/discover']
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=25,check=False)
 require(p.returncode==0 and len(p.stdout)<=65536 and len(p.stderr)<=8192,'contrast outcome unknown')
 manifest=json.loads(p.stdout); require(isinstance(manifest,dict) and isinstance(manifest.get('services'),list) and any(isinstance(x,dict) and x.get('name')=='FenceFixture' for x in manifest['services']),'manifest mismatch')
 require(old.ctl('show',NAME,'-p','MainPID','--value')=='0' and old.ctl('show',NAME,'-p','Job','--value')=='','contrast process unresolved')
 result={'schema':1,'epoch_sha256':approved['epoch_sha256'],'http2_discovery':True,'service':'FenceFixture','unit_terminal':True,'invocations':False}
 old.store(DONE,base.canonical(result)+b'\n',0o600);return result
