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
import pathlib
START=old.ETC/'unix-admin-h2-canary-continuation-started.json';DONE=old.ETC/'unix-admin-h2-canary-continuation-complete.json'
ORIGINAL_SHA='830672ede5bb8abceface915548b243352f9952fbee5477ba1be092c96e6587b'
SOURCE_HASHES=None
STAGES=['start_old','prezero_old','register_old','probe_positive','snapshot_baseline','classify_baseline','retire_old','probe_after','snapshot_postretire','classify_postretire','start_new','prezero_new','dispatch_new_once_lost_response','reconcile_new','restart_restate','snapshot_afterrestart','classify_afterrestart','quiesce']
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,old.ETC/'unix-admin-h2-canary-orchestration-complete.json')),'continuation occupied')
 original=old.read(old.ETC/'unix-admin-h2-canary-orchestration-started.json',0o600,maxsize=196608);require(base.sha(original)==ORIGINAL_SHA,'original intent mismatch')
 require(isinstance(SOURCE_HASHES,dict) and len(SOURCE_HASHES)>=16 and all(isinstance(k,str) and isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v) for k,v in SOURCE_HASHES.items()),'source manifest unavailable')
 epoch_raw=old.read(activation.DONE,0o600);epoch=json.loads(epoch_raw);require(epoch.get('boot_id')==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'boot changed')
 for name in (base.NET,base.SERVER):require(activation.identity(name)==epoch['identities'][name],'epoch identity changed')
 listener=json.loads(old.read(old.ETC/'unix-admin-h2-canary-no-listener-complete.json',0o600));require(set(listener)=={'schema','epoch_sha256','listeners_closed','net_dev','net_ino'} and listener['schema']==1 and listener['epoch_sha256']==base.sha(epoch_raw) and listener['listeners_closed'] is True and type(listener['net_dev']) is int and listener['net_dev']>0 and type(listener['net_ino']) is int and listener['net_ino']>0,'listener proof unavailable')
 for path in ('unix-admin-h2-canary-sdk-old-start-started.json','unix-admin-h2-canary-sdk-new-start-started.json','unix-admin-h2-canary-register-old-started.json','unix-admin-h2-canary-ingress-probe-started.json'):
  require(not os.path.lexists(old.ETC/path),'effect intent already present')
 for name in (package.OLD,package.NEW):
  p=activation.properties(name);require(p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='','SDK not inactive')
 remaining=[]
 for name in (base.NET,base.SERVER):
  start=int(old.ctl('show',name,'-p','ActiveEnterTimestampMonotonic','--value'));remaining.append(1200-(time.monotonic()-start/1000000))
 require(min(remaining)>=900,'insufficient remaining lifetime')
 sdk.ROLE='old';first=sdk.plan()
 return {'schema':1,'original_intent_sha256':ORIGINAL_SHA,'epoch_sha256':base.sha(epoch_raw),'listener_sha256':base.sha(old.read(old.ETC/'unix-admin-h2-canary-no-listener-complete.json',0o600)),'minimum_remaining_seconds':900,'first_stage':first,'sources':SOURCE_HASHES,'stages':STAGES,'scope':'one pre-effect continuation; preserve original failed intent'}
def stage(module,role=None):
 if role is not None:module.ROLE=role
 approved=module.plan();return module.apply(approved)
def apply(approved):
 require(plan()==approved,'continuation changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 stage(sdk,'old');stage(snapshot,'prezero-old');stage(registration,'old');stage(probe)
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
 result={'schema':1,'synthetic_sequence_completed':True,'fixture_quiesced':True,'original_failed_intent_retained':True,'production_accepted':False,'candidate_promoted':False,'final_receipt_sha256':base.sha(old.read(old.ETC/'unix-admin-h2-canary-after-restart-journal.json',0o600)),'quiesce_receipt_sha256':base.sha(old.read(quiesce.DONE,0o600))};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
