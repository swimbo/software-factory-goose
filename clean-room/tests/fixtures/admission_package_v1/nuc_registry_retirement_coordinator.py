"""Fixed one-shot SDK1–4 retirement candidate; not installed or executed.

A fixed one-shot apply candidate retains its transition marker on uncertainty.
It is uninstalled and unrun, and requires review and native fixture proof.
This is not SDK5 admission or a Restate backup/restore producer.
"""
import hashlib,json,os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_v5_manifest_candidate as candidate
import nuc_registry_v5_install as v5
import nuc_registry_sidecar_install as v4
import nuc_registry_process_attestation as attestation
import nuc_private_runtime_install as private_install
import nuc_registry_external_preservation as external

T=candidate.TRANSITION_ID
PREFIXES=('software-factory-goose-private-','software-factory-goose-grant-canary-','software-factory-goose-real-','software-factory-goose-registry-')
UNITS=tuple([p+s for p in PREFIXES for s in ('intake.socket','worker.socket')]+[p+'launch.socket' for p in PREFIXES[1:]]+[p+'runtime.service' for p in PREFIXES]+[p+'register.service' for p in PREFIXES])
SERVICES=tuple(p+'runtime.service' for p in PREFIXES)
START=gate.ROOT/'history'/(T+'.retirement-started.json')
DONE=gate.ROOT/'history'/(T+'.retirement-complete.json')
TRANSPORT=gate.ROOT/'history'/(T+'.retirement-transport.json')
PROBE_UNIT='sfactory-registry-retire-listeners-'+T.lower()+'.service'
PROBE=old.PREFIX/'registry-retired-listener-probe.py'
PROBE_SHA='865d2da0aa12000f5897ef57b3cc5085d8f68e78a3515464d27c047acb12f10f'

def require(v,m):
 if not v:raise RuntimeError(m)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def properties(unit):
 keys='LoadState,ActiveState,SubState,MainPID,InvocationID,Job,ControlGroup,Names,FragmentPath,DropInPaths,ConditionResult,ExecStart'
 raw=old.ctl('show',unit,'--property='+keys,'--all','--no-pager');out={}
 for line in raw.splitlines():
  key,sep,value=line.partition('=');require(sep and key not in out,'manager output unavailable');out[key]=value
 return out
def paths(unit):
 return gate.ROOT/'history'/(T+'.'+unit+'.retired'),old.UNIT/(unit+'.d')/('90-sfactory-retired-'+T.lower()+'.conf')
def expected_dropin(unit):
 marker,_=paths(unit);return ('[Unit]\nConditionPathExists=!'+str(marker)+'\n').encode()
def observe(unit):
 p=properties(unit);require(p.get('LoadState')=='loaded' and p.get('Names')==unit and p.get('FragmentPath')==str(old.UNIT/unit) and p.get('Job','')=='','unit identity unavailable')
 raw=old.read(old.UNIT/unit,0o644);p['fragment_sha256']=sha(raw)
 dropins={}
 for path in p.get('DropInPaths','').split():
  require(path.startswith(str(old.UNIT)+'/') and path not in dropins,'untrusted drop-in path');dropins[path]=sha(old.read(pathlib.Path(path),0o644))
 p['dropin_sha256']=dropins
 group=p.get('ControlGroup','')
 if group:
  require(group=='/system.slice/'+unit,'unexpected cgroup path');cg=os.lstat(pathlib.Path('/sys/fs/cgroup')/group.lstrip('/'));require(stat.S_ISDIR(cg.st_mode) and cg.st_uid==0,'cgroup unavailable');p['cgroup_identity']=[cg.st_dev,cg.st_ino]
 return p

def preservation(cfg):
 """Read the protected namespace, PG, and PID1 identities afresh.

 The trusted root manager and fixed installed bootstrap files are the authority;
 this is an observation, not a claim that any unit has been stopped.
 """
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 private_raw=old.read(old.RUN/'private-netns.json',0o600)
 host_raw=old.read(old.RUN/'host-netns.json',0o600)
 private=gate._json(private_raw);host=gate._json(host_raw)
 require(cfg['boot_id']==boot and private.get('role')=='private' and private.get('uid')==0 and private.get('version')==1 and host.get('role')=='host' and host.get('uid')==0 and host.get('version')==1,'namespace provenance unavailable')
 require((private['netns_dev'],private['netns_ino'])==(cfg['namespace_dev'],cfg['namespace_ino']) and (host['netns_dev'],host['netns_ino'])==(cfg['host_namespace_dev'],cfg['host_namespace_ino']) and (private['netns_dev'],private['netns_ino'])!=(host['netns_dev'],host['netns_ino']),'namespace identity changed')
 for path,digest,mode in ((pathlib.Path(attestation.ANCHOR),attestation.ANCHOR_SHA,0o755),(old.UNIT/attestation.ANCHOR_UNIT,attestation.ANCHOR_UNIT_SHA,0o644),(pathlib.Path(attestation.DROPIN),attestation.DROPIN_SHA,0o644)):
  old.read(path,mode,digest)
 hostunit='software-factory-goose-private-host-net.service';host_anchor=attestation.properties(hostunit)
 require(host_anchor.get('ActiveState')=='active' and host_anchor.get('Names')==hostunit and host_anchor.get('FragmentPath')==str(old.UNIT/hostunit) and host_anchor.get('MainPID')==str(host['pid']) and host_anchor.get('NoNewPrivileges')=='yes' and host_anchor.get('CapabilityBoundingSet')=='','host anchor unavailable')
 require(host_anchor.get('ExecStart','').startswith('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+attestation.ANCHOR+' host ; ignore_errors=no ;') and host_anchor['ExecStart'].count('{ path=')==1,'host anchor executable changed')
 anchor=attestation.properties(attestation.ANCHOR_UNIT)
 require(anchor.get('ActiveState')=='active' and anchor.get('Names')==attestation.ANCHOR_UNIT and anchor.get('FragmentPath')==str(old.UNIT/attestation.ANCHOR_UNIT) and anchor.get('DropInPaths')==attestation.DROPIN and anchor.get('MainPID')==str(private['pid']) and anchor.get('PrivateNetwork')=='yes' and anchor.get('NoNewPrivileges')=='yes' and anchor.get('CapabilityBoundingSet')=='','anchor unavailable')
 require(anchor.get('ExecStart','').startswith('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+attestation.ANCHOR+' private ; ignore_errors=no ;') and anchor['ExecStart'].count('{ path=')==1,'anchor executable changed')
 pgunit='software-factory-goose-private-postgres.service';pg=observe(pgunit)
 require(pg.get('ActiveState')=='active' and pg.get('MainPID','').isdigit() and int(pg['MainPID'])>1 and re.fullmatch('[0-9a-f]{32}',pg.get('InvocationID','')),'postgres unavailable')
 pgdata=pathlib.Path('/var/lib/software-factory-goose/journal/pgdata');st=os.lstat(pgdata)
 require(stat.S_ISDIR(st.st_mode) and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(2004,2004,0o700),'postgres data identity unavailable')
 genesis=gate._json(old.read(old.ETC/'private-genesis.json',0o644))
 pg_tree_sha256=private_install.verify_postgres_tree();sid=private_install.postgres_system_id(pgdata)
 require(genesis['boot_id']==boot and (st.st_dev,st.st_ino)==(genesis['pgdata_dev'],genesis['pgdata_ino']) and sid==genesis['postgres_system_id'],'postgres identity changed')
 h_pid=host['pid'];h_ticks=attestation.ticks(h_pid);h_identity=observe(hostunit)
 a_pid=private['pid'];p_pid=int(pg['MainPID']);a_ticks=attestation.ticks(a_pid);p_ticks=attestation.ticks(p_pid);a_identity=observe(attestation.ANCHOR_UNIT)
 require(h_identity['MainPID']==str(h_pid) and re.fullmatch('[0-9a-f]{32}',h_identity['InvocationID']) and observe(hostunit)==h_identity and attestation.ticks(h_pid)==h_ticks and a_identity['MainPID']==str(a_pid) and re.fullmatch('[0-9a-f]{32}',a_identity['InvocationID']) and attestation.properties(attestation.ANCHOR_UNIT).get('MainPID')==str(a_pid) and observe(attestation.ANCHOR_UNIT)==a_identity and observe(pgunit)==pg and attestation.ticks(a_pid)==a_ticks and attestation.ticks(p_pid)==p_ticks,'support process changed')
 inventory=external.collect()
 return {'external':inventory,'external_sha256':external.digest(inventory),'boot_id':boot,'private_manifest_sha256':sha(private_raw),'host_manifest_sha256':sha(host_raw),'private_namespace':[private['netns_dev'],private['netns_ino']],'host_namespace':[host['netns_dev'],host['netns_ino']],'host_anchor':h_identity,'host_anchor_start_ticks':h_ticks,'anchor':a_identity,'anchor_pid':a_pid,'anchor_start_ticks':a_ticks,'postgres':pg,'postgres_start_ticks':p_ticks,'pgdata_dev':st.st_dev,'pgdata_ino':st.st_ino,'postgres_tree_sha256':pg_tree_sha256,'postgres_system_id':sid}

def plan_locked():
 require(os.geteuid()==0 and os.getegid()==0,'root required')
 require(not any(os.path.lexists(p) for p in (START,DONE,TRANSPORT)),'transition already attempted')
 head=gate.verify_head();registry=gate._protected_read(gate.REGISTRY,0o644,65536);require(sha(registry)==head['manifest_sha256'],'registry head changed')
 cfg,config,_=v5.proposed_config();evidence=old.read(v4.EVIDENCE,0o644);manifest=candidate.build(registry,config,evidence)
 require(manifest['transition_id']==T and not any(os.path.lexists(gate.ROOT/'history'/(T+s)) for s in ('.plan.json','.old-registry.json')),'transition history occupied')
 old.read(PROBE,0o755,PROBE_SHA,65536)
 units={}
 for unit in UNITS:
  marker,dropin=paths(unit);require(not os.path.lexists(marker) and not os.path.lexists(dropin),'retirement fence occupied')
  if os.path.lexists(dropin.parent):old.directory(dropin.parent,0,0,0o755)
  units[unit]=observe(unit)
  require(units[unit]['ActiveState'] in ('active','inactive') and (unit not in SERVICES or (units[unit]['ActiveState']=='active' and units[unit]['MainPID'].isdigit() and int(units[unit]['MainPID'])>1 and re.fullmatch('[0-9a-f]{32}',units[unit]['InvocationID']))),'unit state unavailable')
 preserved=preservation(cfg)
 return {'schema':1,'transition_id':T,'preservation':preserved,'old_manifest_sha256':manifest['old_manifest_sha256'],'new_manifest_sha256':manifest['new_manifest_sha256'],'new_manifest':manifest['manifest'],'sdk5_config_sha256':manifest['config_sha256'],'evidence_sha256':manifest['evidence_sha256'],'units':units,'probe_sha256':PROBE_SHA,'scope':'fixed retirement/closed gate only; no registration or backup'}

def plan():
 with gate._gate(gate.ROOT,True,0,2000,0o710,0o440):return plan_locked()

def capture_transport(path,preservation):
 shared,transport=external.collect_with_transport();require(shared==preservation['external'],'external inventory changed');old.store(path,canonical(transport),0o600)

def terminal(unit, before):
 """Require the fixed unit to be stopped and its observed cgroup empty."""
 now=properties(unit)
 require(now.get('LoadState')=='loaded' and now.get('Names')==unit and now.get('FragmentPath')==str(old.UNIT/unit) and now.get('ActiveState')=='inactive' and ((unit.endswith('.socket') and now.get('MainPID') in (None,'','0')) or (unit.endswith('.service') and now.get('MainPID')=='0')) and now.get('Job','')=='','unit terminal state unavailable')
 group=before.get('ControlGroup','')
 if group:
  require(group=='/system.slice/'+unit,'unexpected old cgroup')
  path=pathlib.Path('/sys/fs/cgroup')/group.lstrip('/')
  try:st=os.lstat(path)
  except FileNotFoundError:st=None
  if st is not None:
   require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and [st.st_dev,st.st_ino]==before.get('cgroup_identity'),'cgroup unavailable')
   values=dict(line.split() for line in (path/'cgroup.events').read_text().splitlines())
   require(values.get('populated')=='0','cgroup still populated')
 return now

def verify_loaded_fence(unit,before):
 marker,dropin=paths(unit);current=observe(unit)
 expected=dict(before['dropin_sha256']);expected[str(dropin)]=sha(expected_dropin(unit))
 require(current['dropin_sha256']==expected,'loaded drop-ins changed')
 for path in expected:
  if path!=str(dropin) and pathlib.Path(path).name>dropin.name:
   raw=old.read(pathlib.Path(path),0o644)
   require(re.search(rb'(?m)^\s*ConditionPathExists\s*=',raw) is None,'later condition override unavailable')
 return current

def assert_original(unit,before):
 current=observe(unit)
 for key in ('LoadState','Names','FragmentPath','fragment_sha256','MainPID','InvocationID','ControlGroup','cgroup_identity'):
  require(current.get(key)==before.get(key),'unit identity changed before stop')
 require(current.get('Job','')=='','unit has pending job')

def listener_observation(expected_namespace):
 """Run only the pinned probe in the fixed private anchor's PID1 namespace."""
 require(old.ctl('show',PROBE_UNIT,'-p','LoadState','--value')=='not-found','probe unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines()
 require(paths,'unit paths unavailable');stem=PROBE_UNIT.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
 for parent in map(pathlib.Path,paths):
  for item in [parent/PROBE_UNIT,parent/(PROBE_UNIT+'.d'),parent/'service.d']+[parent/(p+'.service.d') for p in prefixes]:require(not os.path.lexists(item),'probe unit collision')
 argv=['/usr/bin/systemd-run','--unit='+PROBE_UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+attestation.ANCHOR_UNIT,'--property=BindsTo='+attestation.ANCHOR_UNIT,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=15s','/usr/bin/python3','-I','-B',str(PROBE)]
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=25,check=False)
 require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'listener probe outcome unknown')
 obj=gate._json(p.stdout);require(obj=={'schema':1,'ports':[9081,9082,9083,9084],'listeners_and_established_absent':True,'namespace_dev':expected_namespace[0],'namespace_ino':expected_namespace[1]},'listener observation mismatch')
 require(old.ctl('show',PROBE_UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',PROBE_UNIT,'-p','Job','--value')=='','listener probe unresolved')
 return obj

def apply(reviewed):
 """Close admission, permanently fence and stop only the exact reviewed units.

 Any failure retains the transition marker and partial evidence for a separate
 recovery procedure. This operation never starts SDK5 or changes Restate/PG.
 """
 gate._trusted_ancestors()
 with gate._gate(gate.ROOT,True,0,2000,0o710,0o440) as fd:
  require(plan_locked()==reviewed,'retirement plan changed')
  intent={'schema':1,'transition_id':T,'old_manifest_sha256':reviewed['old_manifest_sha256'],'new_manifest_sha256':reviewed['new_manifest_sha256']}
  with gate._transition_already_locked(fd,intent):
   old.store(START,canonical(reviewed),0o600)
   capture_transport(TRANSPORT,reviewed['preservation'])
   for unit in UNITS:
    marker,dropin=paths(unit)
    old.store(marker,b'retired\n',0o600)
    if not os.path.lexists(dropin.parent):
     os.mkdir(dropin.parent,0o755);os.chmod(dropin.parent,0o755);old.syncdir(dropin.parent.parent)
    old.directory(dropin.parent,0,0,0o755)
    old.store(dropin,expected_dropin(unit),0o644)
   old.ctl('daemon-reload')
   for unit in UNITS:
    marker,dropin=paths(unit);old.read(marker,0o600,sha(b'retired\n'));old.read(dropin,0o644,sha(expected_dropin(unit)))
    verify_loaded_fence(unit,reviewed['units'][unit])
   # Socket activation is closed before service shutdown; exact prior process
   # identity is checked immediately before each manager stop.
   for unit in UNITS:
    assert_original(unit,reviewed['units'][unit]);old.ctl('stop',unit);terminal(unit,reviewed['units'][unit])
   # PID1 must itself reject each fenced start. This does not release the gate.
   for unit in UNITS:
    old.ctl('start',unit)
    require(properties(unit).get('ConditionResult')=='no','fenced restart not refused')
    terminal(unit,reviewed['units'][unit])
   observed=listener_observation(reviewed['preservation']['private_namespace'])
   cfg,_,_=v5.proposed_config();require(preservation(cfg)==reviewed['preservation'],'support identity changed')
   result={'schema':1,'transition_id':T,'plan_sha256':sha(canonical(reviewed)),'transition_intent_sha256':sha(canonical(intent)),'units':{u:terminal(u,reviewed['units'][u]) for u in UNITS},'listener_observation':observed,'preservation':reviewed['preservation'],'sdk5_started':False,'restate_stopped':False}
   old.store(DONE,canonical(result),0o600)
   return result
