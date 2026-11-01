"""Compare retained history and replay fixed SDK5 read-only handlers, while retaining the closed gate.

Caller supplies only pinned source bytes; fixed transition, targets, units and
endpoints are derived from protected state. Unknown keeps the gate closed.
"""
import os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_retirement_coordinator as retired
import nuc_registry_offline_backup as backup
import nuc_registry_restore_history as history
import nuc_registry_v5_transition_plan as trans
import nuc_registry_v5_unix_registration as registration
import nuc_registry_unix_restate_activate as unix
import nuc_registry_v5_runtime_activate as sdk
import nuc_registry_attestation_profiles as profiles
T=retired.T;LIVE_SOURCE=None;HANDLER_SOURCE=None
LIVE_SHA='2c81c4dfe4090f345e4aff9c6da6c2efd36075bc20465d8ce45ab4b41b13e773';HANDLER_SHA='c8629c7db802e1f9605be97dff44bf0bcf67d0c7a4a9e2ea84c3e3e5fe748733'
LIVE=old.PREFIX/'registry-v5-live-history-probe.py';HANDLER=old.PREFIX/'registry-v5-handler-replay-probe.py'
INSTALL=gate.ROOT/'history'/(T+'.replay-install-started.json');START=gate.ROOT/'history'/(T+'.after-started.json');DONE=gate.ROOT/'history'/(T+'.replay.json')
UNITS={'state':'sfactory-registry-v5-state-'+T.lower()+'.service','handlers':'sfactory-registry-v5-handlers-'+T.lower()+'.service'}
def require(v,m):
 if not v:raise RuntimeError(m)
def plan_locked():
 require(os.geteuid()==0 and isinstance(LIVE_SOURCE,bytes) and backup.sha(LIVE_SOURCE)==LIVE_SHA and isinstance(HANDLER_SOURCE,bytes) and backup.sha(HANDLER_SOURCE)==HANDLER_SHA and not any(os.path.lexists(p) for p in (LIVE,HANDLER,INSTALL,START,DONE)),'replay occupied')
 retired_raw,_=backup.retirement_state();planraw=old.read(trans.PLAN,0o600);plan=gate._json(planraw);intent=gate._json(gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000));require(plan.get('transition_id')==T and intent=={'schema':1,'transition_id':T,'old_manifest_sha256':plan['old_manifest_sha256'],'new_manifest_sha256':plan['new_manifest_sha256']} and backup.sha(gate._protected_read(gate.REGISTRY,0o644,65536))==plan['new_manifest_sha256'],'transition unavailable')
 oldraw=old.read(trans.OLD,0o600,plan['old_manifest_sha256'],65536);baseline_raw=old.read(history.DONE,0o600,maxsize=4*1024*1024);baseline=gate._json(baseline_raw);targets=history.derive_restore_targets(oldraw,lambda name:gate._protected_read(gate.REGISTRY.parent/name,0o644,65536));require(baseline.get('transition_id')==T and baseline.get('registry_sha256')==plan['old_manifest_sha256'] and [(x['service'],x['key']) for x in baseline['histories']]==[(x['service'],x['key']) for x in targets],'history baseline changed')
 deployment=gate.resolve_deployment(plan,gate.ROOT/'history');u=gate._json(old.read(unix.DONE,0o600));s=gate._json(old.read(sdk.DONE,0o600));require(retired.observe(unix.provision.UNIT)==u['identity'] and retired.observe(sdk.UNIT)==s['identity'] and not os.path.lexists(sdk.v5.MARKER),'runtime unavailable')
 manifest=gate._protected_read(gate.REGISTRY,0o644,65536);profile=gate.registry_profile(manifest);require(profile['profile']=='sdk5','SDK5 profile unavailable');att=gate._protected_read(profile['attestation'],0o600,16384);attj=gate._json(att);require(attj.get('config_sha256')==plan['new_manifest_sha256'] and attj.get('boot_id')==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'SDK5 attestation unavailable');old.read(profile['probe'],0o755,profile['probe_sha256'],10000000)
 for unit in UNITS.values():history.unit_available(unit)
 return {'schema':1,'transition_id':T,'plan_sha256':backup.sha(planraw),'baseline_sha256':backup.sha(baseline_raw),'retirement_sha256':backup.sha(retired_raw),'manifest_sha256':plan['new_manifest_sha256'],'old_manifest_sha256':plan['old_manifest_sha256'],'attestation_sha256':backup.sha(att),'deployment_id':deployment,'targets':targets,'namespace':u['namespace'],'socket_dev':u['socket_dev'],'socket_ino':u['socket_ino'],'scope':'compare retained state then invoke fixed SDK5 read-only handlers; retain closed gate pending independently enforced admission'}
def plan():
 with backup.locked():return plan_locked()
def invoke(unit,program,argv,request,timeout,limit):
 args=['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+retired.attestation.ANCHOR_UNIT,'--property=BindsTo='+retired.attestation.ANCHOR_UNIT,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=256M','--property=TasksMax=16','--property=RuntimeMaxSec='+str(timeout-10)+'s','/usr/bin/python3','-I','-B',str(program),*argv]
 p=subprocess.run(args,input=backup.canonical(request),env=old.ENV,capture_output=True,timeout=timeout,check=False);require(p.returncode==0 and len(p.stdout)<=limit and len(p.stderr)<=8192,'replay observer outcome unknown');out=gate._json(p.stdout);require(old.ctl('show',unit,'-p','MainPID','--value')=='0' and old.ctl('show',unit,'-p','Job','--value')=='','replay observer unresolved');return out
def apply(approved):
 with backup.locked():
  require(plan_locked()==approved,'replay plan changed');old.store(INSTALL,backup.canonical(approved),0o600);old.store(LIVE,LIVE_SOURCE,0o755);old.store(HANDLER,HANDLER_SOURCE,0o755);old.read(LIVE,0o755,LIVE_SHA);old.read(HANDLER,0o755,HANDLER_SHA)
  old.store(START,backup.canonical({'schema':1,'transition_id':T,'phase':'state-and-handlers'}),0o600)
  ns=approved['namespace'];state=invoke(UNITS['state'],LIVE,['restore'],{'schema':1,'targets':approved['targets'],'namespace_dev':ns[0],'namespace_ino':ns[1],'socket_dev':approved['socket_dev'],'socket_ino':approved['socket_ino']},130,4*1024*1024)
  baseline=gate._json(old.read(history.DONE,0o600,approved['baseline_sha256'],4*1024*1024));require(state=={'schema':1,'histories':baseline['histories']},'retained history differs')
  request={'schema':1,'namespace_dev':ns[0],'namespace_ino':ns[1],'socket_dev':approved['socket_dev'],'socket_ino':approved['socket_ino'],'deployment_id':approved['deployment_id'],'targets':approved['targets']};out=invoke(UNITS['handlers'],HANDLER,[],request,310,65536)
  require(set(out)=={'schema','deployment_id','replayed_calls','results_sha256','raw_values_exposed'} and out['schema']==1 and out['deployment_id']==approved['deployment_id'] and type(out['replayed_calls']) is int and len(approved['targets'])<=out['replayed_calls']<=256 and isinstance(out['results_sha256'],str) and re.fullmatch('[0-9a-f]{64}',out['results_sha256']) and out['raw_values_exposed'] is False,'handler replay unavailable')
  current,_=backup.retirement_state();require(backup.sha(current)==approved['retirement_sha256'] and retired.observe(unix.provision.UNIT)==gate._json(old.read(unix.DONE,0o600))['identity'] and retired.observe(sdk.UNIT)==gate._json(old.read(sdk.DONE,0o600))['identity'],'runtime changed')
  oldraw=old.read(trans.OLD,0o600,approved['old_manifest_sha256'],65536);manifest=gate._json(oldraw);receipt={'schema':1,'transition_id':T,'old_manifest_sha256':approved['old_manifest_sha256'],'new_manifest_sha256':approved['manifest_sha256'],'prior_catalogs_sha256':backup.sha(__import__('nuc_registry_replay_coordinator').canonical(manifest['entries'])),'prior_catalog_count':len(manifest['entries']),'replayed_catalog_count':len(manifest['entries']),'deployment_id':approved['deployment_id'],'attestation_sha256':approved['attestation_sha256'],'producer_sha256':HANDLER_SHA,'plan_sha256':approved['plan_sha256']}
  old.store(DONE,backup.canonical(receipt),0o600)
  return {'schema':1,'transition_id':T,'gate_closed':True,'historical_targets':len(approved['targets']),'replayed_calls':out['replayed_calls'],'results_sha256':out['results_sha256'],'promotion':False}
