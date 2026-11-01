"""Create-only installation of two pinned read-only v5 admission observers."""
import hashlib,json,os
import nuc_grant_sidecar_install as old
import nuc_registry_admission_observe as observe
SOURCES=None
PINS={'registry-admin-deny-probe.py':observe.DENY_SHA,'registry-admission-journal-probe.py':observe.JOURNAL_SHA}
START=old.ETC/'registry-admission-probes-install-started.json';DONE=old.ETC/'registry-admission-probes-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'
def plan():
 require(os.geteuid()==0 and isinstance(SOURCES,dict) and set(SOURCES)==set(PINS),'probe source unavailable')
 for name,digest in PINS.items():require(isinstance(SOURCES[name],bytes) and 0<len(SOURCES[name])<=65536 and hashlib.sha256(SOURCES[name]).hexdigest()==digest,'probe source changed')
 old.directory(old.PREFIX,0,0,0o755);old.directory(old.ETC,0,0,0o711);require(not any(os.path.lexists(p) for p in (START,DONE,observe.DENY,observe.JOURNAL)),'probe installation occupied')
 return {'schema':1,'sources':PINS,'scope':'create-only read-only observer code; no unit or socket access'}
def apply(reviewed):
 require(plan()==reviewed,'probe install plan changed');old.store(START,canonical(reviewed),0o600)
 for name in sorted(PINS):old.store(old.PREFIX/name,SOURCES[name],0o755);old.read(old.PREFIX/name,0o755,PINS[name],65536)
 result={'schema':1,'installed':True,'executed':False,'activated':False};old.store(DONE,canonical(result),0o600);return result
