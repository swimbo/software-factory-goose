"""SDK5 admission adapter. Caller holds registry shared admission lock.

The receipt producer is not installed or pinned yet. Verification cannot pass
until that producer and its complete ingress/retirement protocol are reviewed.
"""
import errno,hashlib,json,os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_attestation_profiles as profiles
import nuc_registry_retirement_coordinator as retirement
import nuc_sdk5_admission_receipt as contract
RECEIPT=old.ETC/'registry-v5-admission-complete.json'
PRODUCER=old.PREFIX/'registry-v5-admission-producer'
PRODUCER_SHA256=None
ADMIN=pathlib.Path('/var/lib/software-factory-goose/journal/restate/sfgoose-private/admin.sock')
def require(v,m):
 if not v:raise RuntimeError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def verify():
 require(PRODUCER_SHA256 is not None,'reviewed SDK5 admission producer unavailable')
 old.read(PRODUCER,0o755,PRODUCER_SHA256,10_000_000)
 head=gate.verify_head();require(head['transition_id']==retirement.T,'transition scope changed')
 manifest=old.read(old.ETC/'catalog-registry.json',0o644,head['manifest_sha256']);profile=profiles.select_for_registry(manifest,lambda path:old.read(path,0o644));require(profile['profile']=='sdk5','SDK5 profile unavailable')
 att=old.read(profile['attestation'],0o600,head['attestation_sha256']);attestation=json.loads(att)
 history=gate.ROOT/'history';replay=gate._json(gate._protected_read(history/(head['transition_id']+'.replay.json'),0o600,16384));deployment=replay['deployment_id']
 start=gate._json(old.read(retirement.START,0o600,maxsize=1_000_000));end=gate._json(old.read(retirement.DONE,0o600,maxsize=1_000_000));require(end.get('transition_id')==head['transition_id'] and set(end.get('units',{}))==set(retirement.UNITS) and end.get('plan_sha256')==sha(retirement.canonical(start)),'retirement receipt unavailable')
 for unit in retirement.UNITS:
  marker,drop=retirement.paths(unit);old.read(marker,0o600,sha(b'retired\n'));old.read(drop,0o644,sha(retirement.expected_dropin(unit)));require(str(drop) in retirement.properties(unit).get('DropInPaths','').split(),'retirement fence unavailable');retirement.terminal(unit,start['units'][unit])
 for path,mode in ((ADMIN.parents[0],0o755),(ADMIN.parents[1],0o755),(ADMIN.parents[2],0o700)):old.directory(path,2004,2004,mode)
 st=os.lstat(ADMIN);require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink)==(2004,2004,0o700,1),'admin socket unavailable')
 try:os.getxattr(ADMIN,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'admin socket ACL unavailable')
 else:raise RuntimeError('admin socket ACL forbidden')
 expected={'producer_sha256':PRODUCER_SHA256,'boot_id':head['boot_id'],'private_namespace_dev':attestation['netns_dev'],'private_namespace_ino':attestation['netns_ino'],'registry_sha256':head['manifest_sha256'],'transition_id':head['transition_id'],'deployment_id':deployment,'process_manifest_sha256':head['attestation_sha256'],'admin_socket_dev':st.st_dev,'admin_socket_ino':st.st_ino}
 raw=old.read(RECEIPT,0o600,maxsize=contract.MAX_BYTES);contract.validate(raw,expected)
 live=subprocess.run([str(PRODUCER),'--verify-live'],env=old.ENV,capture_output=True,timeout=175,check=False);require(live.returncode==0 and len(live.stdout)<=4096 and len(live.stderr)<=4096 and gate._json(live.stdout)=={'schema':1,'admission_sha256':sha(raw),'boot_id':head['boot_id'],'transition_id':head['transition_id'],'registry_sha256':head['manifest_sha256'],'private_namespace_dev':attestation['netns_dev'],'private_namespace_ino':attestation['netns_ino'],'old_listeners_absent':True,'old_established_absent':True,'admin_unix_only':True,'no_overlapping_work':True,'overlap_scope':'retired-sdk-targets-excluding-sdk5','retirement_conditions_effective':True},'live ingress fence unavailable')
 probe=profile['probe'];old.read(probe,0o755,profile['probe_sha256'],10_000_000);p=subprocess.run([str(probe)],env=old.ENV,capture_output=True,timeout=50,check=False);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192 and gate._json(p.stdout)=={'service_attested':True,'grant_requested':False},'SDK5 attestation unavailable')
 require(gate.verify_head()==head,'registry head changed')
 return {'schema':1,'head':head,'admission_sha256':sha(raw),'sdk5_process_attestation_sha256':head['attestation_sha256'],'deployment_id':deployment}
