"""Create-only pinned production evaluator package; no unit, claim or evaluation."""
import hashlib,json,os
import nuc_grant_sidecar_install as old
PINS = {'nuc_grant_sidecar_install.py': 'c8d3ebb2ba4707fdb2600564a1ef3bbc558e7c433cc09413df51e4d8bf87f3b6',
 'nuc_registry_attestation_profiles.py': '8a5c16086baf538c6d8000f979304f2059467844a1048a3c0cd811c942f7e50a',
 'nuc_registry_eval_backend_v3.py': 'd075a73243f4d1284c72686f4c92baf6e668b3f7a2e1732a77e8e5533786d681',
 'nuc_registry_eval_bootstrap_per_generation.py': '6d4a759f875a27c4c96431efab594585ca0db1139e038d47fcf8eca23b61e033',
 'nuc_registry_eval_broker.py': '708cc142b92d62929f81a692d69be8412b9bfd7037a3020ca24fc54f06b9e8b2',
 'nuc_registry_eval_client_per_generation.py': '84bf8f8ca6a7a1f6fb0da84efd5512078f608913de84b063c6b9a45b426d1de7',
 'nuc_registry_eval_coordinator_per_generation.py': '1aa99e2920f55364bddf53a0da2d2a10854a47a24fe0b546bffe65e7683ccee3',
 'nuc_registry_eval_deadline.py': 'ce390a0e56bd409ef05ccdb336748c4c6433bdaf2d59ff3533a9822185f0564e',
 'nuc_registry_eval_provenance.py': '159564047936286f4904b1ad0b53b6d6adbc99d42bf67029d0b3f66569651334',
 'nuc_registry_eval_runtime_per_generation.py': 'bf08b203ade5def671869bfd1231a29d8fc2253490220c0cb765b6367f6886fb',
 'nuc_registry_eval_server_per_generation.py': '01d52b51188601d157f0dc32e54d22fd4dc46eb2ce459d2a2cafe2bb23c357af',
 'nuc_registry_eval_snapshot_provision.py': '2f047947c8a58fbd08a9d316ce977b0da8f0867e6d4d53fb8fb7882320f848be',
 'nuc_registry_evaluator.py': '5c236c7ccf77b93d3c9ac89f05e9fc464afc8361e13e0aff26eafeb0fd4d1360',
 'nuc_registry_transition_gate.py': '8928d88597ce92132d7c81e4e097a14b2b82cccfdae3b9b7006b991f3b27c0d7'}
SOURCES = None
DEST=old.PREFIX/'evaluator-production'
MANIFEST=old.ETC/'evaluator-package.json'
START=old.ETC/'evaluator-package-install-started.json'
DONE=old.ETC/'evaluator-package-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
def validate_sources(values):
 require(isinstance(values,dict) and set(values)==set(PINS),'package sources unavailable')
 for name,pin in PINS.items():
  raw=values[name];require(isinstance(raw,bytes) and 0<len(raw)<=1000000 and hashlib.sha256(raw).hexdigest()==pin,'package source changed')
 return sum(map(len,values.values()))
def plan():
 require(os.geteuid()==0,'root required');size=validate_sources(SOURCES)
 old.directory(old.PREFIX,0,0,0o755);old.directory(old.ETC,0,0,0o711)
 require(not any(os.path.lexists(p) for p in (DEST,MANIFEST,START,DONE)),'package occupied')
 manifest=canonical({'schema':1,'files':PINS})
 return {'schema':1,'files':PINS,'total_bytes':size,'manifest_sha256':hashlib.sha256(manifest).hexdigest(),'scope':'create-only protected evaluator code; no unit, activation, claim or evaluation'}
def apply(approved):
 require(plan()==approved,'package plan changed');old.store(START,canonical(approved),0o600)
 os.mkdir(DEST,0o710);os.chmod(DEST,0o710);os.chown(DEST,0,2002);old.syncdir(DEST.parent);old.directory(DEST,0,2002,0o710)
 for name,raw in SOURCES.items():
  fd=os.open(DEST/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  try:
   os.fchown(fd,0,2002);os.fchmod(fd,0o440);view=memoryview(raw)
   while view:
    n=os.write(fd,view);require(n>0,'short package write');view=view[n:]
   old.noacl(fd);os.fsync(fd)
  finally:os.close(fd)
 old.syncdir(DEST);old.store(MANIFEST,canonical({'schema':1,'files':PINS}),0o600)
 result={'schema':1,'installed':True,'activated':False,'evaluated':False};old.store(DONE,canonical(result),0o600);return result
