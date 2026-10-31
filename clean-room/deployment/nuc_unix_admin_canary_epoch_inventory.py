"""Exact terminal inventory of owned Unix-admin canary epoch; no restart."""
import json,os,pathlib
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_unix_admin_canary_sdk_install as v3
import nuc_unix_admin_canary_sdk_v4_install as v4
DONE=old.ETC/'unix-admin-canary-epoch1-terminal.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'inventory unavailable')
 before=json.loads(old.read(base.START,0o600));activation=json.loads(old.read(active.DONE,0o600));require(activation.get('fixture_retained_active') is True,'activation receipt unavailable')
 require(base.verify_restate()==before['restate'],'binary changed');old.directory(base.ROOT,0,0,0o711);old.directory(base.DATA,2004,2004,0o700)
 for path,ident in ((base.ROOT,(66306,19142891)),(base.DATA,(66306,19142892))):
  s=os.lstat(path);require((s.st_dev,s.st_ino)==ident,'fixture inode changed')
 old.read(base.CONFIG,0o644,before['config_sha256']);old.read(base.ANCHOR,0o755,before['anchor_sha256']);old.read(base.PROBE,0o755,before['probe_sha256'])
 units={**base.units(),**v3.units(),**v4.units()};result={}
 for name,raw in units.items():
  old.read(old.UNIT/name,0o644,base.sha(raw));p=active.properties(name);require(p.get('LoadState')=='loaded' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','fixture unit not terminal')
  cg=pathlib.Path('/sys/fs/cgroup/system.slice')/name
  if cg.exists():
   fields=dict(x.split() for x in (cg/'cgroup.events').read_text().splitlines());require(fields.get('populated')=='0','fixture cgroup populated');state='present-empty'
  else:state='absent'
  result[name]={'active':p['ActiveState'],'cgroup':state}
 for name in ('sfactory-unix-admin-sdk-preflight.service','sfactory-unix-admin-sdk-preflight-connect.service','sfactory-unix-admin-sdk-preflight-closed.service','sfactory-unix-admin-sdk-preflight-extra-fd.service','sfactory-unix-admin-sdk-fd-diagnostic.service'):
  p=dict(x.split('=',1) for x in old.ctl('show',name,'--property=LoadState,ActiveState,MainPID,Job,ControlGroup','--all','--no-pager').splitlines())
  if p.get('LoadState')=='not-found':result[name]={'active':'not-found','cgroup':'absent'};continue
  require(p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','transient fixture not terminal');result[name]={'active':p['ActiveState'],'cgroup':'manager-empty'}
 for name in ('unix-admin-canary-v4-register-old-started.json','unix-admin-canary-register-old-started.json'):
  require(not os.path.lexists(old.ETC/name),'registration has been attempted')
 require(old.old_snapshot()==before['old'],'existing factory changed')
 path=base.DATA/'sfactory-unix-admin'/'admin.sock';socket_state='present' if os.path.lexists(path) else 'absent'
 return {'schema':1,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'data_dev':66306,'data_ino':19142892,'units':result,'prior_admin_socket':socket_state,'scope':'terminal fixture observation only; no restart or data mutation'}
def apply(approved):
 require(plan()==approved,'inventory changed');old.store(DONE,base.canonical(approved)+b'\n',0o600);return approved
