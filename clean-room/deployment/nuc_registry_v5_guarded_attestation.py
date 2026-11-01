"""SDK5 process attestation participant. Caller holds the root transition EX lock."""
import hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
import nuc_registry_process_attestation as base
import nuc_registry_transition_gate as gate
import nuc_registry_v5_guarded_install as install
ATTEST=old.ETC/'registry-v5-process-attestation.json'
START=old.ETC/'registry-v5-process-attestation-started.json'
UNIT=install.NAME+'runtime.service'
SOCKET=old.RUN/'registry-v5-launch-grant.sock'
def require(v,msg):
 if not v:raise RuntimeError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
def plan(intent):
 guarded=json.loads(old.read(install.DONE,0o600));require(guarded.get('schema')==1 and guarded.get('binary_path')==str(install.BIN) and guarded.get('binary_sha256')==install.SOURCE_SHA and guarded.get('guard_source_sha256')==install.GUARD_SHA and guarded.get('production_features')==['registry-v5'] and guarded.get('canary_feature_enabled') is False and guarded.get('installed_inactive') is True and guarded.get('executed') is False,'guarded package unavailable')
 require(os.geteuid()==0 and re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',intent['transition_id']),'invalid identity')
 require(gate._json(gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000))==intent,'pending transition unavailable')
 require(not os.path.lexists(ATTEST) and not os.path.lexists(START),'attestation already attempted')
 manifest=old.read(old.ETC/'catalog-registry.json',0o644,intent['new_manifest_sha256'])
 parsed=gate._json(manifest);require(parsed['active_intent']==install.INTENT,'unexpected active catalog')
 old.read(install.BIN,0o755,install.SOURCE_SHA,100_000_000)
 unit_data=install.units()[UNIT];old.read(old.UNIT/UNIT,0o644,sha(unit_data))
 for path,digest,mode in [(base.ANCHOR,base.ANCHOR_SHA,0o755),(str(old.UNIT/base.ANCHOR_UNIT),base.ANCHOR_UNIT_SHA,0o644),(base.DROPIN,base.DROPIN_SHA,0o644)]:old.read(pathlib.Path(path),mode,digest,65536)
 entries=[e for e in parsed['entries'] if e['config']=='registry-v5-runtime.json'];require(len(entries)==1,'active registry entry unavailable')
 cfg=json.loads(old.read(old.ETC/'registry-v5-runtime.json',0o644,entries[0]['config_sha256']));require(cfg['sdk_port']==9085 and cfg['intent_id']==install.INTENT and cfg['task_id']==install.TASK and cfg['launch_scope']['generation']==install.GEN and cfg['launch_scope']['catalog_sha256']==entries[0]['catalog_sha256'],'active config mismatch')
 private=json.loads(old.read(old.RUN/'private-netns.json',0o600));host=json.loads(old.read(old.RUN/'host-netns.json',0o600));boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 require(cfg['boot_id']==boot and private['role']=='private' and private['uid']==0 and private['version']==1 and host['role']=='host' and host['uid']==0 and host['version']==1 and (private['netns_dev'],private['netns_ino'])==(cfg['namespace_dev'],cfg['namespace_ino']) and (host['netns_dev'],host['netns_ino'])==(cfg['host_namespace_dev'],cfg['host_namespace_ino']) and (host['netns_dev'],host['netns_ino'])!=(private['netns_dev'],private['netns_ino']),'namespace mismatch')
 p=base.properties(UNIT);a=base.properties(base.ANCHOR_UNIT)
 expected={'LoadState':'loaded','ActiveState':'active','Names':UNIT,'FragmentPath':str(old.UNIT/UNIT),'DropInPaths':'','User':'sfgoose-control','Group':'sfgoose-control','NoNewPrivileges':'yes','CapabilityBoundingSet':'','PrivateNetwork':'yes','BindsTo':base.ANCHOR_UNIT,'JoinsNamespaceOf':base.ANCHOR_UNIT,'ExecStartPre':'','ExecStartPost':'','Environment':'','EnvironmentFiles':'','ControlGroup':'/system.slice/'+UNIT}
 require(all(p.get(k,'' if k in ('ExecStartPre','ExecStartPost','EnvironmentFiles') else None)==v for k,v in expected.items()),'SDK5 unit identity changed')
 require(p.get('ExecStart','').startswith('{ path='+str(install.BIN)+' ; argv[]='+str(install.BIN)+' ; ignore_errors=no ;') and p['ExecStart'].count('{ path=')==1,'SDK5 executable changed')
 require(a.get('LoadState')=='loaded' and a.get('ActiveState')=='active' and a.get('Names')==base.ANCHOR_UNIT and a.get('FragmentPath')==str(old.UNIT/base.ANCHOR_UNIT) and a.get('DropInPaths')==base.DROPIN and a.get('MainPID')==str(private['pid']) and a.get('User')=='root' and a.get('NoNewPrivileges')=='yes' and a.get('CapabilityBoundingSet')=='' and a.get('PrivateNetwork')=='yes','anchor identity changed')
 require(a.get('ExecStart','').startswith('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+base.ANCHOR+' private ; ignore_errors=no ;') and a['ExecStart'].count('{ path=')==1,'anchor executable changed')
 pid=int(p['MainPID']);require(pid>1,'SDK5 process absent');anchor=private['pid'];base.process_status(pid,2000,2000);base.process_status(anchor,0,0)
 cg=pathlib.Path('/sys/fs/cgroup/system.slice')/UNIT;st=os.stat(cg);sock=os.lstat(SOCKET)
 require(st.st_uid==0 and stat.S_ISSOCK(sock.st_mode) and (sock.st_uid,sock.st_gid,stat.S_IMODE(sock.st_mode),sock.st_nlink)==(0,0,0o600,1),'socket or cgroup unavailable')
 try:os.getxattr(SOCKET,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==old.errno.ENODATA,'socket ACL unverified')
 else:raise RuntimeError('socket ACL forbidden')
 binding={'schema':1,'boot_id':boot,'pid':pid,'start_ticks':base.ticks(pid),'binary_sha256':install.SOURCE_SHA,'unit_sha256':sha(unit_data),'config_sha256':sha(manifest),'netns_dev':private['netns_dev'],'netns_ino':private['netns_ino'],'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'socket_dev':sock.st_dev,'socket_ino':sock.st_ino,'anchor_pid':anchor,'anchor_start_ticks':base.ticks(anchor),'anchor_unit_sha256':base.ANCHOR_UNIT_SHA,'anchor_binary_sha256':base.ANCHOR_SHA,'anchor_dropin_sha256':base.DROPIN_SHA}
 require(base.properties(UNIT).get('MainPID')==str(pid) and base.properties(base.ANCHOR_UNIT).get('MainPID')==str(anchor) and base.ticks(pid)==binding['start_ticks'] and base.ticks(anchor)==binding['anchor_start_ticks'],'process changed')
 return binding
def apply(intent,approved):
 require(plan(intent)==approved,'attestation changed');old.store(START,canonical({'transition_id':intent['transition_id'],'binding':approved})+b'\n',0o600)
 raw=canonical(approved)+b'\n';old.store(ATTEST,raw,0o600);return {'attestation_sha256':sha(raw),'pid':approved['pid']}
