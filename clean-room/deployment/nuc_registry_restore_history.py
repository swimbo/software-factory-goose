"""Root-controlled pre-stop history baseline; fixed registry scope, read-only.

 Candidate only: no deployment or service changes. Crash/timeout retains intent.
 A later isolated restore must compare the same targets and normalized hashes.
"""
import nuc_registry_pinned_binary as pinned_binary
import os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_replay_coordinator as replay
import nuc_registry_offline_backup as backup
import nuc_registry_retirement_coordinator as retirement
T=backup.T
PROBE=old.PREFIX/'registry-restore-history-probe-v2.py'
PROBE_SHA='a7eb53947d3105c0aece53ca08b0c812cc1261cf83d4c4f733325edeee1742aa'
UNIT='sfactory-registry-history-'+T.lower()+'-before.service'
START=gate.ROOT/'history'/(T+'.restore-history-started.json')
DONE=gate.ROOT/'history'/(T+'.restore-history-baseline.json')
TRANSPORT=gate.ROOT/'history'/(T+'.restore-history-transport.json')
def require(v,m):
 if not v:raise RuntimeError(m)
def unit_available(name):
 require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','history unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=name.removesuffix('.service')
 for parent in map(pathlib.Path,paths):
  for item in [parent/name,parent/(name+'.d'),parent/'service.d']+[parent/(stem[:i+1]+'.service.d') for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(item),'unit collision')
def derive_restore_targets(raw,read_config):
 base=replay.derive_targets(raw,read_config);manifest=gate._json(raw);items={(x['service'],x['key']) for x in base}
 for entry in manifest['entries']:
  config=read_config(entry['config']);require(backup.sha(config)==entry['config_sha256'],'registry config changed');cfg=gate._json(config);key=cfg.get('intent_id')
  require(isinstance(key,str) and re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',key),'IntakeJournal scope unavailable');items.add(('IntakeJournal',key))
 require(1<=len(items)<=48,'history target bound exceeded')
 return [{'service':service,'key':key} for service,key in sorted(items)]
def plan_locked():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,TRANSPORT,backup.START)),'history capture occupied')
 retired_raw,retired=backup.retirement_state();raw=gate._protected_read(gate.REGISTRY,0o644,65536)
 plan=gate._json(old.read(retirement.START,0o600,maxsize=1000000));require(backup.sha(raw)==plan['old_manifest_sha256'],'registry changed')
 targets=derive_restore_targets(raw,lambda name:gate._protected_read(gate.REGISTRY.parent/name,0o644,65536));old.read(PROBE,0o755,PROBE_SHA,65536);pinned_binary.verify(backup.BINARY,backup.BINARY_SHA)
 restate=retirement.observe(backup.RESTATE);backup.validate_active_restate(restate)
 unit_available(UNIT)
 return {'schema':1,'transition_id':T,'retirement_sha256':backup.sha(retired_raw),'registry_sha256':backup.sha(raw),'preservation':retired['preservation'],'restate':restate,'targets':targets,'probe_sha256':PROBE_SHA,'scope':'read-only bounded post-retirement pre-stop state hashes'}
def plan():
 with backup.locked():return plan_locked()
def invoke(unit,mode,namespace,anchor,targets):
 request={'schema':1,'targets':targets,'namespace_dev':namespace[0],'namespace_ino':namespace[1]}
 args=['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+anchor,'--property=BindsTo='+anchor,'--property=After='+anchor,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=256M','--property=TasksMax=16','--property=RuntimeMaxSec=120s','/usr/bin/python3','-I','-B',str(PROBE),mode]
 p=subprocess.run(args,input=backup.canonical(request),env=old.ENV,capture_output=True,timeout=130,check=False);require(p.returncode==0 and len(p.stdout)<=4*1024*1024 and len(p.stderr)<=4096,'history observation unknown')
 out=gate._json(p.stdout);require(isinstance(out,dict) and set(out)=={'schema','histories'} and out['schema']==1 and isinstance(out['histories'],list) and len(out['histories'])==len(targets),'history response unavailable')
 for x,t in zip(out['histories'],targets):
  require(isinstance(x,dict) and set(x)=={'service','key','rows','invocations'} and x['service']==t['service'] and x['key']==t['key'] and isinstance(x['rows'],list) and len(x['rows'])<=128 and isinstance(x['invocations'],list) and len(x['invocations'])<=128 and all(isinstance(d,str) and re.fullmatch('[0-9a-f]{64}',d) for d in x['invocations']),'history scope changed')
  for row in x['rows']:require(isinstance(row,dict) and set(row)=={'key_sha256','value_sha256'} and all(isinstance(row[k],str) and re.fullmatch('[0-9a-f]{64}',row[k]) for k in row),'history row unavailable')
 require(old.ctl('show',unit,'-p','MainPID','--value')=='0' and old.ctl('show',unit,'-p','Job','--value')=='','history process unresolved')
 return out
def apply(reviewed):
 with backup.locked():
  require(plan_locked()==reviewed,'history plan changed');old.store(START,backup.canonical(reviewed),0o600);retirement.capture_transport(TRANSPORT,reviewed['preservation'])
  out=invoke(UNIT,'before',reviewed['preservation']['private_namespace'],retirement.attestation.ANCHOR_UNIT,reviewed['targets'])
  raw,_=backup.retirement_state();require(backup.sha(raw)==reviewed['retirement_sha256'] and retirement.observe(backup.RESTATE)==reviewed['restate'],'history epoch changed')
  result={'schema':1,'transition_id':T,'plan_sha256':backup.sha(backup.canonical(reviewed)),'registry_sha256':reviewed['registry_sha256'],'histories':out['histories']};old.store(DONE,backup.canonical(result),0o600);return {'schema':1,'baseline_sha256':backup.sha(backup.canonical(result)),'raw_values_exposed':False}
