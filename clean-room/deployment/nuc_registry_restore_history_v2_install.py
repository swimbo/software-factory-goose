"""Create-only install for the fixed read-only history probe; never run it."""
import hashlib,os
import nuc_grant_sidecar_install as old
import nuc_registry_restore_history as history
SOURCE=None
START=old.ETC/'registry-restore-history-probe-v2-install-started.json'
DONE=old.ETC/'registry-restore-history-probe-v2-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and isinstance(SOURCE,bytes) and 0<len(SOURCE)<=65536 and hashlib.sha256(SOURCE).hexdigest()==history.PROBE_SHA,'probe source unavailable')
 old.directory(old.PREFIX,0,0,0o755);old.directory(old.ETC,0,0,0o711)
 require(not any(os.path.lexists(p) for p in (START,DONE,history.PROBE)),'probe install occupied')
 return {'schema':1,'source_sha256':history.PROBE_SHA,'size':len(SOURCE),'target':str(history.PROBE),'scope':'install-only; no admin call'}
def apply(reviewed):
 require(plan()==reviewed,'probe plan changed');old.store(START,history.backup.canonical(reviewed),0o600);old.store(history.PROBE,SOURCE,0o755);old.read(history.PROBE,0o755,history.PROBE_SHA,65536)
 result={'schema':1,'installed':True,'executed':False};old.store(DONE,history.backup.canonical(result),0o600);return result
