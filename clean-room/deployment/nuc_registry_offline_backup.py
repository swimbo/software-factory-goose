"""Fixed offline Restate backup candidate. Uninstalled and never executed.

 A retained transition and exact retirement receipt are prerequisites. This
 stage stops only the reviewed Restate unit, and never restarts any service.
 The copy alone does not establish restorability or authorize cutover.
"""
import nuc_registry_pinned_binary as pinned_binary
import nuc_restate_source_inventory as source_inventory
import contextlib,fcntl,hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_retirement_coordinator as retirement
import nuc_registry_v5_install as v5
import nuc_restate_backup_tree as tree
import nuc_backup_copy_cap_canary as cap_canary

T=retirement.T
RESTATE='software-factory-goose-private-restate.service'
SOURCE=pathlib.Path('/var/lib/software-factory-goose/journal/restate')
DEST=pathlib.Path('/var/lib/software-factory-goose')/('registry-transition-backup-'+T)
START=gate.ROOT/'history'/(T+'.backup-started.json')
DONE=gate.ROOT/'history'/(T+'.backup-complete.json')
TRANSPORT=gate.ROOT/'history'/(T+'.backup-transport.json')
FENCE=gate.ROOT/'history'/(T+'.restate.retired')
DROP=old.UNIT/(RESTATE+'.d')/('90-sfactory-offline-'+T.lower()+'.conf')
BINARY=old.PREFIX/'private-restate'
BINARY_SHA='a45eba5044e331636b9da5a8f37fc901dec4cd3ccfcb10889241f76fe9c209db'

def require(v,m):
 if not v:raise RuntimeError(m)
def canonical(v):return retirement.canonical(v)
def sha(v):return hashlib.sha256(v).hexdigest()
def dropin():return ('[Unit]\nConditionPathExists=!'+str(FENCE)+'\n').encode()
@contextlib.contextmanager
def locked():
 gate._trusted_ancestors();d=gate._directory(gate.ROOT,0,2000,0o710);f=None
 try:
  f=os.open(gate.LOCK,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=d);s=os.fstat(f)
  require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2000,1,0o440),'transition lock unavailable');gate.no_acl(f);fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  yield
 finally:
  if f is not None:os.close(f)
  os.close(d)
def verify_loaded_fence(before):
 current=retirement.observe(RESTATE);expected=dict(before['dropin_sha256']);expected[str(DROP)]=sha(dropin())
 require(current['dropin_sha256']==expected,'Restate loaded drop-ins changed')
 for path in expected:
  if path!=str(DROP) and pathlib.Path(path).name>DROP.name:
   require(re.search(rb'(?m)^\s*ConditionPathExists\s*=',old.read(pathlib.Path(path),0o644)) is None,'later Restate condition override unavailable')
 return current
def retirement_state():
 raw=old.read(retirement.DONE,0o600, maxsize=1000000);record=gate._json(raw)
 require(record.get('schema')==1 and record.get('transition_id')==T and record.get('sdk5_started') is False and record.get('restate_stopped') is False and set(record.get('units',{}))==set(retirement.UNITS),'retirement unavailable')
 plan=gate._json(old.read(retirement.START,0o600,maxsize=1000000));require(record.get('plan_sha256')==sha(canonical(plan)) and plan.get('transition_id')==T,'retirement plan changed')
 intent={'schema':1,'transition_id':T,'old_manifest_sha256':plan['old_manifest_sha256'],'new_manifest_sha256':plan['new_manifest_sha256']}
 require(gate._json(gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000))==intent and record.get('transition_intent_sha256')==sha(canonical(intent)),'transition unavailable')
 for unit in retirement.UNITS:
  marker,drop=retirement.paths(unit);old.read(marker,0o600,sha(b'retired\n'));old.read(drop,0o644,sha(retirement.expected_dropin(unit)));retirement.verify_loaded_fence(unit,plan['units'][unit]);retirement.terminal(unit,plan['units'][unit])
 cfg,_,_=v5.proposed_config();require(retirement.preservation(cfg)==record['preservation'],'preservation changed')
 return raw,record

def validate_active_restate(original):return pinned_binary.validate_restate_command(original)

def plan_locked():
 require(os.geteuid()==0 and os.getegid()==0,'root required')
 require(not any(os.path.lexists(p) for p in (START,DONE,FENCE,DROP,DEST,TRANSPORT)),'backup already attempted')
 raw,record=retirement_state();pinned_binary.verify(BINARY,BINARY_SHA)
 cap_raw=old.read(cap_canary.DONE,0o600);cap=gate._json(cap_raw);cap_start=gate._json(old.read(cap_canary.INTENT,0o600))
 require(cap=={'schema':1,'source_sha256':cap_canary.SOURCE_SHA,'public_copy_equal':True,'restore_equal':True,'uid2004_metadata_equal':True,'no_fowner':True,'production_data':False} and cap_start.get('source_sha256')==cap_canary.SOURCE_SHA and cap_start.get('production_data') is False and cap_start.get('capabilities',{}).get('fowner') is False,'native copy canary unavailable')
 history_raw=old.read(gate.ROOT/'history'/(T+'.restore-history-baseline.json'),0o600,maxsize=4*1024*1024);history=gate._json(history_raw);history_plan=gate._json(old.read(gate.ROOT/'history'/(T+'.restore-history-started.json'),0o600,maxsize=1000000))
 require(history.get('schema')==1 and history.get('transition_id')==T and history.get('plan_sha256')==sha(canonical(history_plan)) and history_plan.get('retirement_sha256')==sha(raw) and history.get('registry_sha256')==history_plan.get('registry_sha256') and isinstance(history.get('histories'),list),'history baseline unavailable')
 original=retirement.observe(RESTATE);validate_active_restate(original);require(original==history_plan['restate'],'history Restate changed')
 old.directory(SOURCE.parent,2004,2004,0o700);st=os.lstat(SOURCE);require(stat.S_ISDIR(st.st_mode) and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(2004,2004,0o755),'Restate data unavailable')
 old.directory(DEST.parent,0,0,0o711)
 if os.path.lexists(DROP.parent):old.directory(DROP.parent,0,0,0o755)
 return {'schema':1,'transition_id':T,'retirement_sha256':sha(raw),'native_copy_canary_sha256':sha(cap_raw),'history_baseline_sha256':sha(history_raw),'preservation':record['preservation'],'restate':original,'source_dev':st.st_dev,'source_ino':st.st_ino,'binary_sha256':BINARY_SHA,'destination':str(DEST),'scope':'stop exact Restate and make one bounded offline copy; no restart or restore'}

def plan():
 with locked():return plan_locked()

def apply(reviewed):
 with locked():
  require(plan_locked()==reviewed,'backup plan changed');old.store(START,canonical(reviewed),0o600)
  retirement.capture_transport(TRANSPORT,reviewed['preservation'])
  old.store(FENCE,b'offline\n',0o600)
  if not os.path.lexists(DROP.parent):os.mkdir(DROP.parent,0o755);os.chmod(DROP.parent,0o755);old.syncdir(DROP.parent.parent)
  old.directory(DROP.parent,0,0,0o755);old.store(DROP,dropin(),0o644);old.ctl('daemon-reload');verify_loaded_fence(reviewed['restate'])
  retirement.assert_original(RESTATE,reviewed['restate']);old.ctl('stop',RESTATE);retirement.terminal(RESTATE,reviewed['restate'])
  old.read(FENCE,0o600,sha(b'offline\n'));old.read(DROP,0o644,sha(dropin()))
  sizing=source_inventory.inspect(SOURCE,DEST.parent);require((sizing['source_dev'],sizing['source_ino'])==(reviewed['source_dev'],reviewed['source_ino']),'offline source changed')
  os.mkdir(DEST,0o700);os.chmod(DEST,0o700);old.syncdir(DEST.parent)
  output=DEST/'restate';os.mkdir(output,0o700);os.chmod(output,0o700);os.chown(output,2004,2004);old.directory(output,2004,2004,0o700);old.syncdir(DEST)
  src=os.open(SOURCE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);dst=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   s=os.fstat(src);require((s.st_dev,s.st_ino)==(reviewed['source_dev'],reviewed['source_ino']),'Restate source changed')
   manifest=tree.copy_tree(src,dst,2004,2004);require(manifest['bytes']==sizing['logical_bytes'],'offline source size changed')
  finally:os.close(src);os.close(dst)
  retirement.terminal(RESTATE,reviewed['restate']);old.read(FENCE,0o600,sha(b'offline\n'));old.read(DROP,0o644,sha(dropin()));verify_loaded_fence(reviewed['restate'])
  current,_=retirement_state();require(sha(current)==reviewed['retirement_sha256'],'retirement changed')
  raw=canonical(manifest);old.store(DEST/'manifest.json',raw,0o600)
  receipt={'schema':1,'transition_id':T,'plan_sha256':sha(canonical(reviewed)),'backup_manifest_sha256':sha(raw),'offline_sizing':sizing,'retirement_sha256':reviewed['retirement_sha256'],'restate_stopped':True,'restore_verified':False}
  old.store(DONE,canonical(receipt),0o600);return receipt
