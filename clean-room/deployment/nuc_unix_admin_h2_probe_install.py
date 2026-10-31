"""Install the fixed H2 probe without running it or changing older fixtures."""
import json,os
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
SOURCE=None;SHA='315bed30437e3d74e1c5d9ec0e313c9b372cf750d71e753c066b426b1e575c2d'
KEEPER=old.PREFIX/'unix-admin-canary-h2-keeper';KEEPER_SHA='d098a8d0f04c281efebcef52addf39520d76cc1bdf88947ffc2fc9dc02ad9188'
DEST=old.PREFIX/'unix-admin-h2-canary-ingress-probe.py';START=old.ETC/'unix-admin-h2-canary-probe-install-started.json';DONE=old.ETC/'unix-admin-h2-canary-probe-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and isinstance(SOURCE,bytes) and base.sha(SOURCE)==SHA,'probe source unavailable')
 require(not any(os.path.lexists(p) for p in (DEST,START,DONE)),'probe occupied');old.directory(old.PREFIX,0,0,0o755);old.read(KEEPER,0o755,KEEPER_SHA,10_000_000)
 proof=json.loads(old.read(old.ETC/'h2-keeper-reconcile-complete.json',0o600));require(proof=={'schema':1,'initial_and_reuse':True,'held_and_new_denied':True,'extra_fd_denied':True,'control_terminal_success':True,'network_stopped':True,'original_attempt_retained':True,'mutation':False},'native keeper proof unavailable')
 return {'schema':1,'source_sha256':SHA,'keeper_sha256':KEEPER_SHA,'destination':str(DEST),'scope':'create-only fresh fixed H2 probe; no execution'}
def apply(approved):
 require(plan()==approved,'probe plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);old.store(DEST,SOURCE,0o755);old.read(DEST,0o755,SHA)
 result={'schema':1,'installed':True,'executed':False,'source_sha256':SHA,'keeper_sha256':KEEPER_SHA};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
