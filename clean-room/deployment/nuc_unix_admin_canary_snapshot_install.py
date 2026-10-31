"""Create-only fixed synthetic Restate snapshot helper; never query on install."""
import json,os
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
OPS_SOURCE=None;OPS_SHA='a630111130056492a61f757ac98700e011d4e1389aa98d3cb8509075a79359bd'
LOST_SOURCE=None;LOST_SHA='87dc14ec1e6d25803600ba83421dfe3cee6312f10217ee2d672dc58055c6e3dd'
ADMIN_SOURCE=None;ADMIN_SHA='e345adc2f6dbe7f89f44e46f2127c0b7b397bb41701911fbcfe9fb5410074056'
DEST=old.PREFIX/'unix-admin-canary-snapshot-ops.py';START=old.ETC/'unix-admin-canary-snapshot-install-started.json';DONE=old.ETC/'unix-admin-canary-snapshot-install-complete.json'
LOST=old.PREFIX/'unix-admin-canary-lost-ops.py'
ADMIN=old.PREFIX/'unix-admin-canary-fixed-ops-v2.py'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and isinstance(OPS_SOURCE,bytes) and base.sha(OPS_SOURCE)==OPS_SHA and isinstance(LOST_SOURCE,bytes) and base.sha(LOST_SOURCE)==LOST_SHA and isinstance(ADMIN_SOURCE,bytes) and base.sha(ADMIN_SOURCE)==ADMIN_SHA,'fixed source unavailable')
 require(not any(os.path.lexists(p) for p in (DEST,LOST,ADMIN,START,DONE)),'snapshot destination occupied');old.directory(old.PREFIX,0,0,0o755)
 return {'schema':1,'source_sha256':OPS_SHA,'destination':str(DEST),'lost_sha256':LOST_SHA,'lost_destination':str(LOST),'admin_sha256':ADMIN_SHA,'admin_destination':str(ADMIN),'scope':'create-only fixed synthetic query and registration helpers; no query or registration'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);old.store(DEST,OPS_SOURCE,0o755);old.store(LOST,LOST_SOURCE,0o755);old.store(ADMIN,ADMIN_SOURCE,0o755)
 require(base.sha(old.read(DEST,0o755,OPS_SHA))==OPS_SHA and base.sha(old.read(LOST,0o755,LOST_SHA))==LOST_SHA and base.sha(old.read(ADMIN,0o755,ADMIN_SHA))==ADMIN_SHA,'installed helper changed');result={'installed':True,'queried':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
