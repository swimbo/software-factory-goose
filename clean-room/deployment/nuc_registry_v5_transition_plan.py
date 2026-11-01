"""Derive the exact fixed transition plan using read-only old deployment metadata."""
import os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_offline_backup as backup
import nuc_registry_retirement_coordinator as retired
import nuc_registry_v5_catalog_publish as catalog
import nuc_registry_unix_restate_activate as unix
import nuc_registry_v5_runtime_activate as sdk
T=retired.T;PROBE_SOURCE=None;PROBE_SHA='625450eaf25f899ca4898f0221c4146997f4122fb87ee2a7d900e0be3260a1b4';PROBE=old.PREFIX/'registry-transition-old-deployment-probe.py';UNIT='sfactory-registry-old-deployment-'+T.lower()+'.service';START=gate.ROOT/'history'/(T+'.transition-plan-started.json');PLAN=gate.ROOT/'history'/(T+'.plan.json');OLD=gate.ROOT/'history'/(T+'.old-registry.json')
def require(v,m):
 if not v:raise RuntimeError(m)
def plan_locked():
 require(os.geteuid()==0 and isinstance(PROBE_SOURCE,bytes) and backup.sha(PROBE_SOURCE)==PROBE_SHA and not any(os.path.lexists(p) for p in (PROBE,START,PLAN,OLD)),'transition plan occupied')
 old.directory(old.PREFIX,0,0,0o755);retired_raw,_=backup.retirement_state();publication=gate._json(old.read(catalog.DONE,0o600));activation=gate._json(old.read(unix.DONE,0o600));sdkstate=gate._json(old.read(sdk.DONE,0o600));require(all(x.get('transition_id')==T for x in (publication,activation,sdkstate)) and sdkstate.get('bootstrap_marker_absent') is True and sdkstate.get('registered') is False and not os.path.lexists(sdk.v5.MARKER),'staged runtime unavailable')
 prior=old.read(catalog.BACKUP,0o644,publication['prior_sha256']);require(backup.sha(gate._protected_read(gate.REGISTRY,0o644,65536))==publication['manifest_sha256'] and retired.observe(unix.provision.UNIT)==activation['identity'] and retired.observe(sdk.UNIT)==sdkstate['identity'],'live scope changed')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','metadata unit occupied');roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for parent in map(pathlib.Path,roots):
  for n in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(parent/n),'unit collision')
 return {'schema':1,'transition_id':T,'prior_sha256':backup.sha(prior),'manifest_sha256':publication['manifest_sha256'],'retirement_sha256':backup.sha(retired_raw),'unix_activation_sha256':backup.sha(old.read(unix.DONE,0o600)),'sdk_activation_sha256':backup.sha(old.read(sdk.DONE,0o600)),'probe_sha256':PROBE_SHA,'namespace':activation['namespace'],'socket_dev':activation['socket_dev'],'socket_ino':activation['socket_ino'],'scope':'fixed read-only old deployment metadata and root transition plan'}
def plan():
 with backup.locked():return plan_locked()
def apply(approved):
 with backup.locked():
  require(plan_locked()==approved,'transition plan changed');old.store(START,backup.canonical(approved),0o600);old.store(PROBE,PROBE_SOURCE,0o755);old.read(PROBE,0o755,PROBE_SHA)
  args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+retired.attestation.ANCHOR_UNIT,'--property=BindsTo='+retired.attestation.ANCHOR_UNIT,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=30s','/usr/bin/python3','-I','-B',str(PROBE)]
  request=backup.canonical({'namespace_dev':approved['namespace'][0],'namespace_ino':approved['namespace'][1],'socket_dev':approved['socket_dev'],'socket_ino':approved['socket_ino']});p=subprocess.run(args,input=request,env=old.ENV,capture_output=True,timeout=40,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'metadata outcome unknown');out=gate._json(p.stdout);require(set(out)=={'schema','deployment_id','uri','service_count'} and out['schema']==1 and out['uri']=='http://127.0.0.1:9084' and out['service_count']==4 and isinstance(out['deployment_id'],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',out['deployment_id']),'old deployment unavailable');require(old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','metadata process unresolved')
  prior=old.read(catalog.BACKUP,0o644,approved['prior_sha256']);require(retired.observe(unix.provision.UNIT)==gate._json(old.read(unix.DONE,0o600))['identity'] and retired.observe(sdk.UNIT)==gate._json(old.read(sdk.DONE,0o600))['identity'],'runtime identity changed')
  plan={'schema':1,'transition_id':T,'old_manifest_sha256':approved['prior_sha256'],'new_manifest_sha256':approved['manifest_sha256'],'old_deployment_id':out['deployment_id'],'old_sdk_uri':'http://127.0.0.1:9084','new_deployment_id':None,'new_sdk_uri':'http://127.0.0.1:9085'};old.store(OLD,prior,0o600);old.store(PLAN,backup.canonical(plan),0o600);return {'schema':1,'transition_id':T,'plan_sha256':backup.sha(backup.canonical(plan)),'old_registry_sha256':backup.sha(prior),'gate_closed':True}
