"""One retained-state final classification and quiesce; never repeat effects."""
import json,os
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_9086_classify as classify
import nuc_unix_admin_h2_9086_quiesce as quiesce
START=old.ETC/'unix-admin-h2-canary-9086-final-continuation-started.json';DONE=old.ETC/'unix-admin-h2-canary-9086-final-continuation-complete.json';SOURCE_HASHES=None
ORIGINAL_SHA='07066091952c228d060d204da5e6ab176e68def1ffb73d57fb82561f7ef29b2c'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,old.ETC/'unix-admin-h2-canary-9086-orchestration-complete.json',old.ETC/'unix-admin-h2-canary-after-restart-journal.json')),'continuation occupied')
 raw=old.read(old.ETC/'unix-admin-h2-canary-9086-orchestration-started.json',0o600,maxsize=196608);require(base.sha(raw)==ORIGINAL_SHA,'original intent mismatch')
 diag_raw=old.read(old.ETC/'unix-admin-h2-canary-afterrestart-diagnostic.json',0o600,maxsize=196608);diag=json.loads(diag_raw);snapshot=old.read(old.ETC/'unix-admin-h2-canary-snapshot-afterrestart-complete.json',0o600,maxsize=196608);require(diag.get('schema')==1 and diag.get('snapshot_sha256')==base.sha(snapshot),'snapshot diagnostic mismatch')
 require(isinstance(SOURCE_HASHES,dict) and len(SOURCE_HASHES)>=16 and all(isinstance(k,str) and isinstance(v,str) and len(v)==64 and all(c in '0123456789abcdef' for c in v) for k,v in SOURCE_HASHES.items()),'source manifest unavailable')
 final=classify.plan();require(final.get('schema')==1 and final.get('snapshot_sha256')==base.sha(snapshot),'classification unavailable')
 return {'schema':1,'original_sha256':ORIGINAL_SHA,'diagnostic_sha256':base.sha(diag_raw),'classification':final,'sources':SOURCE_HASHES,'stages':['classify_afterrestart','quiesce'],'scope':'one fixed retained-state finalization; no repeated invocation or registration'}
def apply(approved):
 require(plan()==approved,'continuation changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 final=classify.apply(approved['classification']);require(final==approved['classification'],'classification changed');q=quiesce.plan();stopped=quiesce.apply(q)
 require(stopped=={'schema':1,'sdk_listeners_closed':True,'admin_socket_absent':True,'owned_units_terminal':True,'fixture_data_retained':True,'old_work_retained':True,'production_changed':False},'quiesce unknown')
 result={'schema':1,'synthetic_sequence_completed':True,'fixture_quiesced':True,'9082_outcome':'unknown','original_failed_intent_retained':True,'production_accepted':False,'candidate_promoted':False,'final_receipt_sha256':base.sha(old.read(old.ETC/'unix-admin-h2-canary-after-restart-journal.json',0o600)),'quiesce_receipt_sha256':base.sha(old.read(quiesce.DONE,0o600))};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
