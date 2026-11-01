#!/usr/bin/python3
"""Fixed root SDK5 admission publisher and live revalidator, uninstalled.

 The caller holds the matching registry lock for verification; pending publication
 holds the exclusive transition lock itself. No task, path, proof, result or selector is accepted from the caller.
 UID-scoped read-only PID1 observers run fresh each time. Unknown publication
 retains its intent and never automatically retries.
"""
import hashlib,json,os,pathlib,re,stat,subprocess,sys
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_retirement_coordinator as retirement
import nuc_registry_v5_install as v5
import nuc_registry_admission_observe as observe
import nuc_registry_offline_backup as backup
import nuc_registry_pinned_binary as pinned_binary
import nuc_sdk5_admission_receipt as contract

SELF=old.PREFIX/'registry-v5-admission-producer-v2';RECEIPT=old.ETC/'registry-v5-admission-complete.json';START=old.ETC/'registry-v5-admission-started.json'
PACKAGE=old.ETC/'registry-v5-admission-package-v2-complete.json'
GUARDED=old.ETC/'registry-v5-guarded-runtime-complete.json';NATIVE=old.ETC/'sdk5-fdguard-canary-recovery-complete.json';NATIVE_START=old.ETC/'sdk5-fdguard-canary-started.json'
ADMIN=pathlib.Path('/var/lib/software-factory-goose/journal/restate/sfgoose-private/admin.sock')
H2=old.ETC/'unix-admin-h2-canary-9086-final-continuation-complete.json';H2_FINAL=old.ETC/'unix-admin-h2-canary-after-restart-journal.json';H2_STOP=old.ETC/'unix-admin-h2-canary-9086-quiesce-complete.json'
GUARD_SHA='986a8b7e0e86493245fda320db979779056c1cc209ee49a539bebead8029f2c3';ENTRY_SHA='9446aa194b14406715b5c4787cf9a8c6550864715c1eb2bd21145c913d914766';CANARY_SHA='e6c12ae30c1903566f05e46b9baa064ac65bd9e7e873bd78204e5ab66d256beb';GUARDED_BINARY_SHA='20c91c027d5a8cf4d430e59aa5afeb365df7c54177ce0ebb5f54f86f5f416349';SOURCE_COMMIT='6e0537c686264a8f4f661862ddac710960a0400d'

def require(v,m):
 if not v:raise RuntimeError(m)
def sha(v):return hashlib.sha256(v).hexdigest()
def canonical(v):return contract.canonical(v)
def rootjson(path,limit=65536):
 raw=old.read(path,0o600,maxsize=limit);return raw,gate._json(raw)
def guarded_binary(att):
 native_raw,native=rootjson(NATIVE);_,native_start=rootjson(NATIVE_START,1000000)
 require(isinstance(native,dict) and set(native)=={'schema','positive','extra_connected_fd_denied','positive_invocation_id','negative_invocation_id','fixture_stopped','registration','original_attempt_retained'} and native['schema']==1 and native['positive'] is True and native['extra_connected_fd_denied'] is True and native['fixture_stopped'] is True and native['registration'] is False and native['original_attempt_retained'] is True and all(isinstance(native[k],str) and re.fullmatch('[0-9a-f]{32}',native[k]) and native[k]!='0'*32 for k in ('positive_invocation_id','negative_invocation_id')) and native['positive_invocation_id']!=native['negative_invocation_id'] and native_start.get('binary',{}).get('sha256')==CANARY_SHA,'native guard proof unavailable')
 _,g=rootjson(GUARDED);keys={'schema','binary_path','prior_binary_sha256','binary_sha256','guard_source_sha256','entrypoint_sha256','build_source_commit','production_features','canary_feature_enabled','native_guard_receipt_sha256','native_guard_binary_sha256','backup_path','installed_inactive','executed'}
 require(set(g)==keys and g['schema']==1 and g['binary_path']==str(v5.BIN) and g['prior_binary_sha256']==v5.SOURCE_SHA and g['guard_source_sha256']==GUARD_SHA and g['entrypoint_sha256']==ENTRY_SHA and g['production_features']==['registry-v5'] and g['canary_feature_enabled'] is False and g['native_guard_receipt_sha256']==sha(native_raw) and g['native_guard_binary_sha256']==CANARY_SHA and g['installed_inactive'] is True and g['executed'] is False and isinstance(g['backup_path'],str) and g['backup_path']==str(old.PREFIX/'private-registry-v5-sidecar.pre-guard') and g['build_source_commit']==SOURCE_COMMIT and g['binary_sha256']==GUARDED_BINARY_SHA and att.get('binary_sha256')==g['binary_sha256'],'guarded SDK5 provenance unavailable')
 pinned_binary.verify(v5.BIN,g['binary_sha256']);pinned_binary.verify(pathlib.Path(g['backup_path']),v5.SOURCE_SHA)
 return g

def h2_evidence():
 raw,result=rootjson(H2);final_raw,final=rootjson(H2_FINAL,1000000);stop_raw,stop=rootjson(H2_STOP)
 _,continuation=rootjson(old.ETC/'unix-admin-h2-canary-9086-final-continuation-started.json',1000000);original_raw,_=rootjson(old.ETC/'unix-admin-h2-canary-9086-orchestration-started.json',1000000)
 require(continuation.get('schema')==1 and continuation.get('original_sha256')==sha(original_raw) and continuation.get('classification')==final and continuation.get('stages')==['classify_afterrestart','quiesce'],'H2 continuation provenance unavailable')
 require(result.get('schema')==1 and result.get('synthetic_sequence_completed') is True and result.get('fixture_quiesced') is True and result.get('9082_outcome')=='unknown' and result.get('original_failed_intent_retained') is True and result.get('production_accepted') is False and result.get('candidate_promoted') is False and result.get('final_receipt_sha256')==sha(final_raw) and result.get('quiesce_receipt_sha256')==sha(stop_raw) and stop=={'schema':1,'sdk_listeners_closed':True,'admin_socket_absent':True,'owned_units_terminal':True,'fixture_data_retained':True,'old_work_retained':True,'production_changed':False},'H2 proof unavailable')
 old.read(old.ETC/'unix-admin-h2-canary-register-new-started.json',0o600);require(not os.path.lexists(old.ETC/'unix-admin-h2-canary-register-new-complete.json'),'original 9082 outcome changed')
 return sha(raw)

def snapshot(pending=False):
 require(os.geteuid()==0,'root required');raw=gate._protected_read(gate.REGISTRY,0o644,65536);profile=gate.registry_profile(raw);require(profile['profile']=='sdk5','SDK5 head unavailable')
 att_raw=gate._protected_read(profile['attestation'],0o600,16384);att=gate._json(att_raw)
 if pending:
  intent=gate._json(gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000));plan=gate._json(old.read(gate.ROOT/'history'/(retirement.T+'.plan.json'),0o600, maxsize=16384));boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  require(set(plan)=={'schema','transition_id','old_manifest_sha256','new_manifest_sha256','old_deployment_id','old_sdk_uri','new_deployment_id','new_sdk_uri'} and type(plan['schema']) is int and plan['schema']==1 and isinstance(plan.get('old_manifest_sha256'),str) and re.fullmatch(r'[0-9a-f]{64}',plan['old_manifest_sha256']) and plan['old_manifest_sha256']!=sha(raw),'pending plan invalid')
  require(intent=={'schema':1,'transition_id':retirement.T,'old_manifest_sha256':plan.get('old_manifest_sha256'),'new_manifest_sha256':sha(raw)} and plan.get('transition_id')==retirement.T and plan.get('new_manifest_sha256')==sha(raw) and att.get('config_sha256')==sha(raw) and att.get('boot_id')==boot,'pending authority unavailable')
  head={'transition_id':retirement.T,'boot_id':boot,'manifest_sha256':sha(raw),'attestation_sha256':sha(att_raw)}
 else:
  head=gate.verify_head();require(head['transition_id']==retirement.T and sha(att_raw)==head['attestation_sha256'],'transition unavailable')
 guard=guarded_binary(att)
 old.read(profile['probe'],0o755,profile['probe_sha256'],10000000);p=subprocess.run([str(profile['probe'])],env=old.ENV,capture_output=True,timeout=50,check=False);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=4096 and gate._json(p.stdout)=={'service_attested':True,'grant_requested':False},'live SDK5 attestation unavailable')
 _,start=rootjson(retirement.START,1000000);end_raw,end=rootjson(retirement.DONE,1000000);require(end.get('transition_id')==retirement.T and end.get('plan_sha256')==sha(retirement.canonical(start)) and set(end.get('units',{}))==set(retirement.UNITS),'retirement receipt unavailable')
 for unit in retirement.UNITS:
  marker,drop=retirement.paths(unit);old.read(marker,0o600,sha(b'retired\n'));old.read(drop,0o644,sha(retirement.expected_dropin(unit)));retirement.verify_loaded_fence(unit,start['units'][unit]);retirement.terminal(unit,start['units'][unit]);require(retirement.properties(unit).get('ConditionResult')=='no','retirement condition unavailable')
 for directory,mode in ((ADMIN.parents[0],0o755),(ADMIN.parents[1],0o755),(ADMIN.parents[2],0o700)):old.directory(directory,2004,2004,mode)
 st=os.lstat(ADMIN);require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(2004,2004,1,0o700),'admin socket unavailable')
 try:os.getxattr(ADMIN,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==old.errno.ENODATA,'admin socket ACL unavailable')
 else:raise RuntimeError('admin socket ACL forbidden')
 replay=gate._json(gate._protected_read(gate.ROOT/'history'/(retirement.T+'.replay.json'),0o600,16384));deployment=replay.get('deployment_id');require(isinstance(deployment,str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',deployment),'deployment unavailable')
 if pending:
  plan_raw=old.read(gate.ROOT/'history'/(retirement.T+'.plan.json'),0o600,maxsize=16384);plan=gate._json(plan_raw);handler=old.PREFIX/'registry-v5-handler-replay-probe.py';handler_sha='c8629c7db802e1f9605be97dff44bf0bcf67d0c7a4a9e2ea84c3e3e5fe748733';old.read(handler,0o755,handler_sha,65536)
  require(replay.get('schema')==1 and replay.get('transition_id')==retirement.T and replay.get('old_manifest_sha256')==plan.get('old_manifest_sha256') and replay.get('new_manifest_sha256')==head['manifest_sha256'] and replay.get('attestation_sha256')==head['attestation_sha256'] and replay.get('producer_sha256')==handler_sha and replay.get('plan_sha256')==sha(plan_raw) and gate.resolve_deployment(plan,gate.ROOT/'history')==deployment,'pending replay unavailable')
 me=old.read(SELF,0o755,maxsize=1000000);_,package=rootjson(PACKAGE);require(package=={'schema':1,'installed':True,'executed':False,'activated':False,'launcher_sha256':sha(me)},'admission package unavailable');return {'head':head,'attestation':att,'deployment':deployment,'admin_dev':st.st_dev,'admin_ino':st.st_ino,'retirement_sha256':sha(end_raw),'h2_sha256':h2_evidence(),'producer_sha256':sha(me),'guard_binary_sha256':guard['binary_sha256']}

def evidence(binding,pending=False):
 ns=[binding['attestation']['netns_dev'],binding['attestation']['netns_ino']];journal=observe.run('journal',ns,binding['deployment']);deny=observe.run('deny',ns)
 require((journal['admin_dev'],journal['admin_ino'])==(binding['admin_dev'],binding['admin_ino']) and deny=={'schema':1,'admin_access_denied':True},'admin observer binding changed')
 require(snapshot(pending)==binding,'authority changed during observation');return {'journal':journal,'deny':deny,'h2_sha256':binding['h2_sha256']}

def expected(binding):
 h=binding['head'];a=binding['attestation'];return {'producer_sha256':binding['producer_sha256'],'boot_id':h['boot_id'],'private_namespace_dev':a['netns_dev'],'private_namespace_ino':a['netns_ino'],'registry_sha256':h['manifest_sha256'],'transition_id':h['transition_id'],'deployment_id':binding['deployment'],'process_manifest_sha256':h['attestation_sha256'],'admin_socket_dev':binding['admin_dev'],'admin_socket_ino':binding['admin_ino']}

def build_receipt(binding,proof):
 e=expected(binding);retired=[]
 for unit,port in contract.OLD_ENDPOINTS:
  marker,_=retirement.paths(unit);retired.append({'unit':unit,'port':port,'fence_sha256':sha(old.read(marker,0o600)),'stop_receipt_sha256':binding['retirement_sha256'],'no_job':True,'cgroup_empty':True,'listener_closed':True,'serving_fds_closed':True,'restart_denied':True})
 value={'schema':1,**{k:e[k] for k in ('producer_sha256','boot_id','private_namespace_dev','private_namespace_ino','registry_sha256','transition_id')},'sdk5':{'intent_id':contract.SDK5_INTENT,'task_id':contract.SDK5_TASK,'generation':contract.SDK5_GENERATION,'deployment_id':e['deployment_id'],'uri':'http://127.0.0.1:9085','process_manifest_sha256':e['process_manifest_sha256']},'admin':{'socket_dev':e['admin_socket_dev'],'socket_ino':e['admin_socket_ino'],'unix_only':True,'sdk_uid_denied':True,'trusted_journal_uid_allowed':True,'no_inherited_admin_fd':True},'ingress':{'port':8080,'old_forwarding_denied':True,'unresolved_overlap_count':0,'inventory_sha256':sha(canonical(proof['journal']['counts'])),'observation_sha256':sha(canonical(proof))},'retired':retired}
 raw=canonical(value);contract.validate(raw,e);return raw

def plan_locked():
 require(not any(os.path.lexists(x) for x in (START,RECEIPT)),'publication already attempted');binding=snapshot(True)
 return {'schema':1,'binding':binding,'scope':'publish exact prospective SDK5 admission while transition remains closed'}
def plan():
 with backup.locked():return plan_locked()
def apply(reviewed):
 with backup.locked():
  require(plan_locked()==reviewed,'admission plan changed');binding=reviewed['binding'];old.store(START,canonical({'schema':1,'head':binding['head'],'producer_sha256':binding['producer_sha256']}),0o600)
  proof=evidence(binding,True);raw=build_receipt(binding,proof);old.store(RECEIPT,raw,0o600);return {'schema':1,'published':True,'receipt_sha256':sha(raw),'transition_still_closed':True}

def verify_pending():
 # Fixed root coordinator holds the exclusive transition lock.
 binding=snapshot(True);started=gate._json(old.read(START,0o600,maxsize=16384));require(started=={'schema':1,'head':binding['head'],'producer_sha256':binding['producer_sha256']},'admission intent changed');raw=old.read(RECEIPT,0o600,maxsize=contract.MAX_BYTES);receipt=contract.validate(raw,expected(binding));proof=evidence(binding,True)
 require(receipt['ingress']['inventory_sha256']==sha(canonical(proof['journal']['counts'])) and receipt['ingress']['observation_sha256']==sha(canonical(proof)),'pending evidence changed')
 return {'schema':1,'admission_sha256':sha(raw),'transition_id':binding['head']['transition_id'],'manifest_sha256':binding['head']['manifest_sha256'],'attestation_sha256':binding['head']['attestation_sha256'],'boot_id':binding['head']['boot_id'],'transition_still_closed':True}

def verify_live():
 binding=snapshot();started=gate._json(old.read(START,0o600,maxsize=16384));pending_head={k:binding['head'][k] for k in ('transition_id','boot_id','manifest_sha256','attestation_sha256')};require(started=={'schema':1,'head':pending_head,'producer_sha256':binding['producer_sha256']},'admission intent changed');raw=old.read(RECEIPT,0o600,maxsize=contract.MAX_BYTES);receipt=contract.validate(raw,expected(binding));proof=evidence(binding)
 require(receipt['ingress']['inventory_sha256']==sha(canonical(proof['journal']['counts'])) and receipt['ingress']['observation_sha256']==sha(canonical(proof)),'live evidence changed')
 h=binding['head'];a=binding['attestation'];return {'schema':1,'admission_sha256':sha(raw),'boot_id':h['boot_id'],'transition_id':h['transition_id'],'registry_sha256':h['manifest_sha256'],'private_namespace_dev':a['netns_dev'],'private_namespace_ino':a['netns_ino'],'old_listeners_absent':True,'old_established_absent':True,'admin_unix_only':True,'no_overlapping_work':True,'overlap_scope':'retired-sdk-targets-excluding-sdk5','retirement_conditions_effective':True}
if __name__=='__main__':
 try:
  require(sys.argv in ([sys.argv[0],'--verify-pending'],[sys.argv[0],'--verify-live']),'fixed operation required');fn={'--verify-pending':verify_pending,'--verify-live':verify_live}[sys.argv[1]];print(json.dumps(fn(),sort_keys=True,separators=(',',':')))
 except Exception:
  print('SDK5 admission unavailable',file=sys.stderr);raise SystemExit(1)
