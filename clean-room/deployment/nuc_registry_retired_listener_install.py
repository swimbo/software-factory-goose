"""Create-only install for the fixed retired-listener observer; never run it."""
import hashlib,os
import nuc_grant_sidecar_install as old
import nuc_registry_retirement_coordinator as retirement
SOURCE=None
START=old.ETC/'registry-retired-listener-install-started.json'
DONE=old.ETC/'registry-retired-listener-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and isinstance(SOURCE,bytes) and 0<len(SOURCE)<=65536 and hashlib.sha256(SOURCE).hexdigest()==retirement.PROBE_SHA,'probe source unavailable')
 old.directory(old.PREFIX,0,0,0o755);old.directory(old.ETC,0,0,0o711)
 require(not any(os.path.lexists(p) for p in (START,DONE,retirement.PROBE)),'probe install occupied')
 return {'schema':1,'source_sha256':retirement.PROBE_SHA,'size':len(SOURCE),'target':str(retirement.PROBE),'scope':'install-only; no socket observation'}
def apply(reviewed):
 require(plan()==reviewed,'probe plan changed');old.store(START,retirement.canonical(reviewed),0o600);old.store(retirement.PROBE,SOURCE,0o755);old.read(retirement.PROBE,0o755,retirement.PROBE_SHA,65536)
 result={'schema':1,'installed':True,'executed':False};old.store(DONE,retirement.canonical(result),0o600);return result
