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
import nuc_unix_admin_h2_probe_after_recovery as recover
START=old.ETC/'unix-admin-h2-canary-postretire-continuation-started.json';DONE=old.ETC/'unix-admin-h2-canary-postretire-continuation-complete.json'
SOURCE_HASHES=None;HISTORY_SOURCE=None
ORIGINAL_SHA='c6c896d477a2133c796a14b2ec980fd2a5c5f9561da1f467892dda5a92c21231'
STAGES=['recover_probe_after','snapshot_postretire','classify_postretire','start_new','prezero_new','dispatch_new_once_lost_response','reconcile_new','restart_restate','snapshot_afterrestart','observe_history_afterrestart','classify_afterrestart','quiesce']
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,old.ETC/'unix-admin-h2-canary-classification-continuation-complete.json')),'continuation occupied')
 raw=old.read(old.ETC/'unix-admin-h2-canary-classification-continuation-started.json',0o600,maxsize=196608);require(base.sha(raw)==ORIGINAL_SHA,'prior intent mismatch')
 require(isinstance(SOURCE_HASHES,dict) and len(SOURCE_HASHES)>=16 and all(isinstance(k,str) and isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v) for k,v in SOURCE_HASHES.items()),'source manifest unavailable')
 for name in ('unix-admin-h2-canary-after-retirement.json','unix-admin-h2-canary-snapshot-postretire-started.json','unix-admin-h2-canary-sdk-new-start-started.json','unix-admin-h2-canary-register-new-started.json','unix-admin-h2-canary-restate-restart-started.json'):require(not os.path.lexists(old.ETC/name),'later effect attempted')
 history_receipt=json.loads(old.read(old.ETC/'unix-admin-h2-canary-history-output-baseline.json',0o600));require(history_receipt.get('schema')==1 and history_receipt.get('expected_response') is True and history_receipt.get('read_only') is True,'history proof missing')
 recovery=recover.plan();return {'schema':1,'original_sha256':ORIGINAL_SHA,'recovery':recovery,'sources':SOURCE_HASHES,'stages':STAGES,'scope':'one retained post-retirement continuation; no positive replay'}
def stage(module,role=None):
 if role is not None:module.ROLE=role
 approved=module.plan();return module.apply(approved)
def apply(approved):
 require(plan()==approved,'orchestration changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 stage(recover)
 stage(snapshot,'postretire');stage(classify,'postretire');stage(sdk,'new');stage(snapshot,'prezero');stage(lost);stage(snapshot,'reconcile');stage(restart);stage(snapshot,'afterrestart');stage(history,'afterrestart');final=stage(final_classify)
 require(isinstance(final,dict) and final.get('schema')==1 and 'classification' in final,'final classification unavailable')
 stopped=stage(quiesce);require(stopped=={'schema':1,'sdk_listeners_closed':True,'admin_socket_absent':True,'owned_units_terminal':True,'fixture_data_retained':True,'old_work_retained':True,'production_changed':False},'teardown unknown')
 result={'schema':1,'synthetic_sequence_completed':True,'original_failed_intent_retained':True,'fixture_quiesced':True,'production_accepted':False,'candidate_promoted':False,'final_receipt_sha256':base.sha(old.read(old.ETC/'unix-admin-h2-canary-after-restart-journal.json',0o600)),'quiesce_receipt_sha256':base.sha(old.read(quiesce.DONE,0o600))};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
