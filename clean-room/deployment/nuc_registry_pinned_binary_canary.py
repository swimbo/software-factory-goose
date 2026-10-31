"""Read-only native streaming verification of the fixed installed Restate binary."""
import json,os
import nuc_grant_sidecar_install as old
import nuc_registry_pinned_binary as pinned
DONE=old.ETC/'registry-pinned-binary-canary-complete.json';BIN=old.PREFIX/'private-restate';SHA='a45eba5044e331636b9da5a8f37fc901dec4cd3ccfcb10889241f76fe9c209db'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'canary occupied')
 return {'schema':1,'binary':pinned.verify(BIN,SHA),'chunk_bytes':pinned.CHUNK,'scope':'read-only fixed Restate streaming digest; no execution'}
def apply(approved):
 require(plan()==approved,'binary changed');old.store(DONE,(json.dumps(approved,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600);return approved
