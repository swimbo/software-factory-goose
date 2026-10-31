"""One fixed retained-data 9086 recovery; 9082 outcome remains unknown."""
import json,os
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_epoch3 as epoch
import nuc_unix_admin_h2_epoch3_binding as binding
import nuc_unix_admin_h2_9086_install as sdk
import nuc_unix_admin_h2_9086_helpers_install as helpers
import nuc_unix_admin_h2_9086_stage as stage9086
import nuc_unix_admin_h2_9086_restart as restart
import nuc_unix_admin_h2_9086_snapshot_supervisor as snapshot
import nuc_unix_admin_h2_9086_history_output as history
import nuc_unix_admin_h2_9086_classify as classify
import nuc_unix_admin_h2_9086_quiesce as quiesce
START=old.ETC/'unix-admin-h2-canary-9086-orchestration-started.json';DONE=old.ETC/'unix-admin-h2-canary-9086-orchestration-complete.json';SOURCE_HASHES=None
STAGES=['epoch3','bind_retained_data','start_9086','prezero_9086','dispatch_once_9086','reconcile_9086','restart_restate','snapshot_afterrestart','observe_history_afterrestart','classify_afterrestart','quiesce']
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'orchestration occupied')
 require(isinstance(SOURCE_HASHES,dict) and len(SOURCE_HASHES)>=16 and all(isinstance(k,str) and isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v) for k,v in SOURCE_HASHES.items()),'source manifest unavailable')
 require(json.loads(old.read(sdk.DONE,0o600))=={'schema':1,'installed':True,'started':False,'registration':False} and json.loads(old.read(helpers.DONE,0o600))=={'schema':1,'installed':True,'executed':False},'packages unavailable')
 old.read(sdk.BIN,0o755,sdk.SHA,40_000_000);old.read(helpers.QUERY,0o755,helpers.QUERY_SHA);old.read(helpers.LOST,0o755,helpers.LOST_SHA)
 return {'schema':1,'sources':SOURCE_HASHES,'epoch3':epoch.plan(),'stages':STAGES,'scope':'one retained-data synthetic 9086 recovery; never retry 9082'}
def stage(module,role=None):
 if role is not None:module.ROLE=role
 approved=module.plan();return module.apply(approved)
def apply(approved):
 require(plan()==approved,'orchestration changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 stage(epoch);stage(binding);stage(stage9086,'start');stage(stage9086,'prezero');stage(stage9086,'dispatch');stage(stage9086,'reconcile');stage(restart);stage(snapshot,'afterrestart');stage(history,'afterrestart');final=stage(classify)
 require(isinstance(final,dict) and final.get('schema')==1 and 'classification' in final,'final classification unavailable')
 stopped=stage(quiesce);require(stopped=={'schema':1,'sdk_listeners_closed':True,'admin_socket_absent':True,'owned_units_terminal':True,'fixture_data_retained':True,'old_work_retained':True,'production_changed':False},'teardown unknown')
 result={'schema':1,'synthetic_sequence_completed':True,'fixture_quiesced':True,'9082_outcome':'unknown','production_accepted':False,'candidate_promoted':False,'final_receipt_sha256':base.sha(old.read(old.ETC/'unix-admin-h2-canary-after-restart-journal.json',0o600)),'quiesce_receipt_sha256':base.sha(old.read(quiesce.DONE,0o600))};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
