"""Create-only pinned v2 synthetic ingress probe; never execute it here."""
import json,os
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_sdk_install as package
SOURCE=None;SHA='afa21604de2d453f2d719f129fbe537e20799f1abef8c0d4a26efc17665619a8'
DEST=old.PREFIX/'unix-admin-canary-ingress-probe-v2.py';START=old.ETC/'unix-admin-canary-probe-v2-install-started.json';DONE=old.ETC/'unix-admin-canary-probe-v2-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and isinstance(SOURCE,bytes) and base.sha(SOURCE)==SHA,'probe source unavailable')
 require(not any(os.path.lexists(p) for p in (DEST,START,DONE)),'v2 probe destination occupied');old.directory(old.PREFIX,0,0,0o755)
 prior=json.loads(old.read(package.DONE,0o600));require(prior=={'installed':True,'started':False,'registration':False},'v3 package receipt unavailable');old.read(package.PROBE,0o755,package.PROBE_SHA)
 return {'schema':1,'destination':str(DEST),'source_sha256':SHA,'prior_probe_sha256':package.PROBE_SHA,'scope':'create-only fixed probe v2; preserve existing probe; no execution'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);old.store(DEST,SOURCE,0o755);old.read(DEST,0o755,SHA)
 result={'schema':1,'installed':True,'executed':False,'source_sha256':SHA};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
