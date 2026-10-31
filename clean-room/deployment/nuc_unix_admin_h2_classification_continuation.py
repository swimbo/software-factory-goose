"""Run the fixed fresh synthetic H2 sequence once; retain every uncertain phase."""
import json,os,time
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_epoch2 as activation
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
import nuc_unix_admin_h2_history_output as history
START=old.ETC/'unix-admin-h2-canary-classification-continuation-started.json';DONE=old.ETC/'unix-admin-h2-canary-classification-continuation-complete.json'
SOURCE_HASHES=None;HISTORY_SOURCE=None
ORIGINAL_SHA='4264d5f3d0ddb87460c1b7721883793364e50f6ac520a9080f87195199633053'
STAGES=['install_history_helper','observe_history_baseline','classify_baseline','retire_old','probe_after','snapshot_postretire','classify_postretire','start_new','prezero_new','dispatch_new_once_lost_response','reconcile_new','restart_restate','snapshot_afterrestart','observe_history_afterrestart','classify_afterrestart','quiesce']
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,old.ETC/'unix-admin-h2-canary-continuation-complete.json')),'continuation occupied')
 original=old.read(old.ETC/'unix-admin-h2-canary-continuation-started.json',0o600,maxsize=196608);require(base.sha(original)==ORIGINAL_SHA,'original continuation mismatch')
 require(isinstance(SOURCE_HASHES,dict) and len(SOURCE_HASHES)>=16 and all(isinstance(k,str) and isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v) for k,v in SOURCE_HASHES.items()),'source manifest unavailable')
 for name in ('unix-admin-h2-canary-before-journal.json','unix-admin-h2-canary-retirement-started.json','unix-admin-h2-canary-register-new-started.json','unix-admin-h2-canary-restate-restart-started.json'):require(not os.path.lexists(old.ETC/name),'later effect attempted')
 diag_raw=old.read(old.ETC/'unix-admin-h2-canary-baseline-diagnostic.json',0o600,maxsize=196608);diag=json.loads(diag_raw);require(diag.get('schema')==1 and diag.get('snapshot_sha256')==base.sha(old.read(old.ETC/'unix-admin-h2-canary-snapshot-baseline-complete.json',0o600,maxsize=196608)),'baseline diagnostic mismatch')
 epoch=probe.epoch();require(diag.get('epoch_sha256')==epoch,'epoch mismatch')
 receipt=json.loads(old.read(probe.DONE,0o600));p=activation.properties(probe.UNIT);require(p.get('ActiveState')=='active' and p.get('MainPID')==str(receipt['pid']) and p.get('Job','')=='' and old.ctl('show',probe.UNIT,'-p','InvocationID','--value')==receipt['invocation_id'],'probe changed')
 require(time.monotonic()-receipt['start_monotonic_us']/1000000<=600,'insufficient probe lifetime')
 history.SOURCE=HISTORY_SOURCE;history.ROLE='install';history_install=history.plan()
 classify.ROLE='baseline';classification=classify.plan();require(classification.get('schema')==1 and classification.get('snapshot_sha256')==diag['snapshot_sha256'],'classification unavailable')
 return {'schema':1,'original_sha256':ORIGINAL_SHA,'diagnostic_sha256':base.sha(diag_raw),'epoch_sha256':epoch,'classification':classification,'history_install':history_install,'sources':SOURCE_HASHES,'stages':STAGES,'scope':'continue only after actual baseline classification; never replay positive probe'}
def stage(module,role=None):
 if role is not None:module.ROLE=role
 approved=module.plan();return module.apply(approved)
def apply(approved):
 require(plan()==approved,'orchestration changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 stage(history,'install');stage(history,'baseline');stage(classify,'baseline');stage(retire)
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  state=old.ctl('show',probe.UNIT,'-p','ActiveState','--value')
  if state in ('inactive','failed'):break
  time.sleep(.2)
 require(state=='inactive','probe terminal unknown');stage(after)
 stage(snapshot,'postretire');stage(classify,'postretire');stage(sdk,'new');stage(snapshot,'prezero');stage(lost);stage(snapshot,'reconcile');stage(restart);stage(snapshot,'afterrestart');stage(history,'afterrestart');final=stage(final_classify)
 require(isinstance(final,dict) and final.get('schema')==1 and 'classification' in final,'final classification unavailable')
 stopped=stage(quiesce);require(stopped=={'schema':1,'sdk_listeners_closed':True,'admin_socket_absent':True,'owned_units_terminal':True,'fixture_data_retained':True,'old_work_retained':True,'production_changed':False},'teardown unknown')
 result={'schema':1,'synthetic_sequence_completed':True,'original_failed_intent_retained':True,'fixture_quiesced':True,'production_accepted':False,'candidate_promoted':False,'final_receipt_sha256':base.sha(old.read(old.ETC/'unix-admin-h2-canary-after-restart-journal.json',0o600)),'quiesce_receipt_sha256':base.sha(old.read(quiesce.DONE,0o600))};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
