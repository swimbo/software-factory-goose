"""Create-only bootstrap of a root registry admission gate; no launch or restart.

The bootstrap treats the already attested current registry as a baseline. Later
transitions use the separate exact-append/replay protocol. Partial bootstrap stays
closed; no automatic reset or cleanup is provided.
"""
import hashlib,json,os,pathlib
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_replay_coordinator as replay
ID='01M65S00000000000000000001';ROOT=gate.ROOT;HIST=ROOT/'history';BOOTSTRAP=old.ETC/'registry-gate-bootstrap-started.json';DONE=old.ETC/'registry-gate-bootstrap-complete.json'
PROBE_SOURCE=b'';REG_SHA='58a1d4f04a2a8ffe98424bd6e8c29b8a4491faac53346698e4f715017df04e78';ATT_SHA='e7ae655d6aee361836518cf6f750053cb54c535e37b57326d218706915453a7a'

def require(v,msg):
 if not v:raise RuntimeError(msg)
def public_store(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  os.fchown(fd,0,2000);os.fchmod(fd,0o440);st=os.fstat(fd);require((st.st_uid,st.st_gid,st.st_nlink,__import__('stat').S_IMODE(st.st_mode))==(0,2000,1,0o440),'public gate file unavailable');old.noacl(fd)
  view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'gate write failed');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(path.parent)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(x) for x in (ROOT,BOOTSTRAP,DONE,replay.PROBE)),'gate already attempted')
 old.directory(ROOT.parent,0,0,0o711);old.directory(old.PREFIX,0,0,0o755);old.directory(old.ETC,0,0,0o711)
 require(hashlib.sha256(PROBE_SOURCE).hexdigest()==replay.PROBE_SHA,'replay probe source changed')
 reg=old.read(gate.REGISTRY,0o644,REG_SHA);att=old.read(gate.ATTEST,0o600,ATT_SHA);state=json.loads(old.read(old.ETC/'registry-registration-complete.json',0o600))
 deploy=state.get('deployment_id');require(isinstance(deploy,str) and __import__('re').fullmatch(r'dp_[A-Za-z0-9]{1,80}',deploy),'deployment receipt unavailable')
 replay.assert_attestor(reg);targets=replay.derive_targets(reg,lambda name:old.read(gate.REGISTRY.parent/name,0o644));boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 unit='sfactory-registry-replay-'+ID.lower()+'-before.service';require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','bootstrap probe unit occupied')
 return {'boot_id':boot,'registry_sha256':REG_SHA,'attestation_sha256':ATT_SHA,'probe_sha256':replay.PROBE_SHA,'deployment_id':deploy,'targets':targets,'transition_id':ID,'scope':'create-only root gate baseline and read-only prior-history digest; no claim, launch or restart'}
def apply(approved):
 require(plan()==approved,'bootstrap plan changed');old.store(BOOTSTRAP,replay.canonical(approved)+b'\n',0o600)
 os.mkdir(ROOT,0o700);os.chown(ROOT,0,2000);os.chmod(ROOT,0o710);old.syncdir(ROOT.parent);old.directory(ROOT,0,2000,0o710)
 os.mkdir(HIST,0o700);old.syncdir(ROOT);old.directory(HIST,0,0,0o700)
 public_store(ROOT/gate.LOCK,b'');public_store(ROOT/gate.MARKER,replay.canonical({'schema':1,'transition_id':ID,'old_manifest_sha256':REG_SHA,'new_manifest_sha256':REG_SHA})+b'\n')
 old.store(replay.PROBE,PROBE_SOURCE,0o755)
 result=replay.run_probe(ID,'before',approved['targets'],approved['deployment_id'],'http://127.0.0.1:9084')
 replay.assert_attestor(old.read(gate.REGISTRY,0o644,REG_SHA));require(old.read(gate.ATTEST,0o600,ATT_SHA),'registry changed')
 reg=old.read(gate.REGISTRY,0o644,REG_SHA);entries=gate._json(reg)['entries'];intent={'schema':1,'transition_id':ID,'old_manifest_sha256':REG_SHA,'new_manifest_sha256':REG_SHA}
 intent_raw=replay.canonical(intent)+b'\n';snapshot={'schema':1,'transition_id':ID,'histories':result['histories'],'deployment_id':approved['deployment_id'],'deployment_metadata_sha256':result['deployment_metadata_sha256']}
 replay_raw=replay.canonical(snapshot)+b'\n';gate._store_history(HIST,ID+'.old-registry.json',reg);gate._store_history(HIST,ID+'.intent.json',intent_raw);gate._store_history(HIST,ID+'.replay.json',replay_raw)
 complete={'schema':1,'transition_id':ID,'boot_id':approved['boot_id'],'manifest_sha256':REG_SHA,'attestation_sha256':ATT_SHA,'replay_sha256':gate._digest(replay_raw),'intent_sha256':gate._digest(intent_raw)};raw=replay.canonical(complete)+b'\n';gate._store_history(HIST,ID+'.complete.json',raw)
 head={'schema':1,'transition_id':ID,'boot_id':approved['boot_id'],'manifest_sha256':REG_SHA,'attestation_sha256':ATT_SHA,'completion_sha256':gate._digest(raw)}
 d=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:gate._atomic_head(d,replay.canonical(head)+b'\n');os.unlink(gate.MARKER,dir_fd=d);os.fsync(d)
 finally:os.close(d)
 require(gate.verify_head()==head,'bootstrap head unavailable')
 final={'boot_id':approved['boot_id'],'head_sha256':gate._digest(replay.canonical(head)+b'\n'),'target_count':len(approved['targets']),'grant_requested':False,'registry_changed':False}
 old.store(DONE,replay.canonical(final)+b'\n',0o600);return final
