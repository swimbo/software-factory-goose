"""One fixed synthetic canary sequence; every mutation has its own root intent.

Any error stops immediately. Existing per-stage intents and observations remain;
no phase is automatically retried or cleaned up. Source bytes are embedded by
one reviewed bridge, not selected by external callers.
"""
import json,os,time
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_epoch_restart as epoch
import nuc_unix_admin_canary_sdk_v4_preflight as preflight
import nuc_unix_admin_canary_start_v4_old as old_start
import nuc_unix_admin_canary_registration_v4 as registration
import nuc_unix_admin_canary_probe_v2_install as probe_install
import nuc_unix_admin_canary_probe_start as probe
import nuc_unix_admin_canary_snapshot_install as snapshot_install
import nuc_unix_admin_canary_snapshot_supervisor as snapshot
import nuc_unix_admin_canary_classify as classify
import nuc_unix_admin_canary_retire_old as retire
import nuc_unix_admin_canary_probe_after as probe_after
import nuc_unix_admin_canary_start_v4_new as new_start
import nuc_unix_admin_canary_register_lost as lost
import nuc_unix_admin_canary_restate_restart as restart
import nuc_unix_admin_canary_classify_after_restart as final_classify
import nuc_unix_admin_canary_quiesce as quiesce
START=old.ETC/'unix-admin-canary-orchestration-started.json';DONE=old.ETC/'unix-admin-canary-orchestration-complete.json'
SOURCE_HASHES=None;SNAPSHOT_SOURCE=None;LOST_SOURCE=None;ADMIN_SOURCE=None;PROBE_SOURCE=None
STAGES=['install_fixed_helpers','install_probe_v2','start_epoch2','v4_preflight','start_old','prezero_old_uri','register_old','probe_positive','snapshot_baseline','classify_baseline','retire_old','probe_after','snapshot_postretire','classify_postretire','start_new','prezero_new_uri','dispatch_new_once_lost_response','reconcile_new_uri','restart_owned_restate','snapshot_afterrestart','classify_afterrestart','quiesce_owned_fixture']
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'orchestration already attempted')
 require(isinstance(SOURCE_HASHES,dict) and len(SOURCE_HASHES)>=16 and all(isinstance(k,str) and isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v) for k,v in SOURCE_HASHES.items()),'source manifest unavailable')
 snapshot_install.OPS_SOURCE=SNAPSHOT_SOURCE;snapshot_install.LOST_SOURCE=LOST_SOURCE;snapshot_install.ADMIN_SOURCE=ADMIN_SOURCE;probe_install.SOURCE=PROBE_SOURCE
 return {'schema':1,'sources':SOURCE_HASHES,'helper_install':snapshot_install.plan(),'probe_install':probe_install.plan(),'epoch2':epoch.plan(),'stages':STAGES,'scope':'one owned synthetic full sequence; any uncertain phase stops without retry'}
def stage(module,role=None):
 if role is not None:module.ROLE=role
 approved=module.plan();return module.apply(approved)
def apply(approved):
 require(plan()==approved,'orchestration plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 stage(snapshot_install);stage(probe_install);stage(epoch);stage(preflight);stage(old_start);stage(snapshot,'prezero-old');stage(registration,'old');stage(probe)
 stage(snapshot,'baseline');stage(classify,'baseline');stage(retire)
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  state=old.ctl('show',probe.UNIT,'-p','ActiveState','--value')
  if state in ('inactive','failed'):break
  time.sleep(.2)
 require(state=='inactive','probe terminal outcome unknown');stage(probe_after)
 stage(snapshot,'postretire');stage(classify,'postretire');stage(new_start);stage(snapshot,'prezero');stage(lost);stage(snapshot,'reconcile');stage(restart);stage(snapshot,'afterrestart');final=stage(final_classify)
 require(isinstance(final,dict) and final.get('schema')==1 and 'classification' in final,'final classification unavailable')
 stopped=stage(quiesce);require(stopped=={'schema':1,'sdk_listeners_closed':True,'admin_socket_absent':True,'owned_units_terminal':True,'fixture_data_retained':True,'old_work_retained':True,'production_changed':False},'fixture teardown unverified')
 result={'schema':1,'synthetic_sequence_completed':True,'fixture_quiesced':True,'production_accepted':False,'candidate_promoted':False,'final_receipt_sha256':base.sha(old.read(old.ETC/'unix-admin-canary-after-restart-journal.json',0o600)),'quiesce_receipt_sha256':base.sha(old.read(quiesce.DONE,0o600))};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
