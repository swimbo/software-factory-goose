"""Run the fixed fresh synthetic H2 sequence once; retain every uncertain phase."""
import json,os,time
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as activation
import nuc_unix_admin_h2_sdk_install as package
import nuc_unix_admin_h2_helpers_install as helpers
import nuc_unix_admin_h2_probe_install as probe_install
import nuc_unix_admin_h2_sdk_start as sdk
import nuc_unix_admin_h2_snapshot_supervisor as snapshot
import nuc_unix_admin_h2_registration as registration
import nuc_unix_admin_h2_probe_start as probe
import nuc_unix_admin_h2_probe_after as after
import nuc_unix_admin_h2_classify as classify
import nuc_unix_admin_h2_retire_old as retire
import nuc_unix_admin_h2_register_lost as lost
import nuc_unix_admin_h2_restate_restart as restart
import nuc_unix_admin_h2_classify_after_restart as final_classify
import nuc_unix_admin_h2_quiesce as quiesce
START=old.ETC/'unix-admin-h2-canary-orchestration-started.json';DONE=old.ETC/'unix-admin-h2-canary-orchestration-complete.json'
SOURCE_HASHES=None;PROBE_SOURCE=None
STAGES=['install_probe','activate','start_old','prezero_old','register_old','probe_positive','snapshot_baseline','classify_baseline','retire_old','probe_after','snapshot_postretire','classify_postretire','start_new','prezero_new','dispatch_new_once_lost_response','reconcile_new','restart_restate','snapshot_afterrestart','classify_afterrestart','quiesce']
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'orchestration already attempted')
 require(isinstance(SOURCE_HASHES,dict) and len(SOURCE_HASHES)>=16 and all(isinstance(k,str) and isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v) for k,v in SOURCE_HASHES.items()),'source manifest unavailable')
 require(json.loads(old.read(package.DONE,0o600))=={'schema':1,'installed':True,'started':False,'registration':False} and json.loads(old.read(helpers.DONE,0o600))=={'installed':True,'queried':False},'fixed packages unavailable')
 probe_install.SOURCE=PROBE_SOURCE
 return {'schema':1,'sources':SOURCE_HASHES,'probe_install':probe_install.plan(),'activation':activation.plan(),'stages':STAGES,'scope':'one fresh owned synthetic H2 sequence; stop on any unknown'}
def stage(module,role=None):
 if role is not None:module.ROLE=role
 approved=module.plan();return module.apply(approved)
def apply(approved):
 require(plan()==approved,'orchestration changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 stage(probe_install);stage(activation);stage(sdk,'old');stage(snapshot,'prezero-old');stage(registration,'old');stage(probe)
 stage(snapshot,'baseline');stage(classify,'baseline');stage(retire)
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  state=old.ctl('show',probe.UNIT,'-p','ActiveState','--value')
  if state in ('inactive','failed'):break
  time.sleep(.2)
 require(state=='inactive','probe terminal unknown');stage(after)
 stage(snapshot,'postretire');stage(classify,'postretire');stage(sdk,'new');stage(snapshot,'prezero');stage(lost);stage(snapshot,'reconcile');stage(restart);stage(snapshot,'afterrestart');final=stage(final_classify)
 require(isinstance(final,dict) and final.get('schema')==1 and 'classification' in final,'final classification unavailable')
 stopped=stage(quiesce);require(stopped=={'schema':1,'sdk_listeners_closed':True,'admin_socket_absent':True,'owned_units_terminal':True,'fixture_data_retained':True,'old_work_retained':True,'production_changed':False},'teardown unknown')
 result={'schema':1,'synthetic_sequence_completed':True,'fixture_quiesced':True,'production_accepted':False,'candidate_promoted':False,'final_receipt_sha256':base.sha(old.read(old.ETC/'unix-admin-h2-canary-after-restart-journal.json',0o600)),'quiesce_receipt_sha256':base.sha(old.read(quiesce.DONE,0o600))};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
