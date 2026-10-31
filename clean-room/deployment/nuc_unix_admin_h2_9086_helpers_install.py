"""Install only fixed 9086 synthetic query and lost-ACK helpers."""
import os
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
QUERY_SOURCE=None;LOST_SOURCE=None
QUERY_SHA='71b4da400901bee5b264dc6c70bfb723617d491e671867a31dbdaff44a140168';LOST_SHA='b4b46c0cf4ca2780686bd63dc1b7218090568f12f4c4ba00709e8230887cf51d'
QUERY=old.PREFIX/'unix-admin-h2-canary-9086-query.py';LOST=old.PREFIX/'unix-admin-h2-canary-9086-lost.py';START=old.ETC/'unix-admin-h2-canary-9086-helpers-started.json';DONE=old.ETC/'unix-admin-h2-canary-9086-helpers-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and isinstance(QUERY_SOURCE,bytes) and isinstance(LOST_SOURCE,bytes) and base.sha(QUERY_SOURCE)==QUERY_SHA and base.sha(LOST_SOURCE)==LOST_SHA and not any(os.path.lexists(p) for p in (QUERY,LOST,START,DONE)),'helpers unavailable')
 old.directory(old.PREFIX,0,0,0o755);return {'schema':1,'query_sha256':QUERY_SHA,'lost_sha256':LOST_SHA,'scope':'create-only fixed synthetic 9086 helpers; no request'}
def apply(approved):
 require(plan()==approved,'helper plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);old.store(QUERY,QUERY_SOURCE,0o755);old.store(LOST,LOST_SOURCE,0o755);old.read(QUERY,0o755,QUERY_SHA);old.read(LOST,0o755,LOST_SHA)
 result={'schema':1,'installed':True,'executed':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
