"""Inventory the exact expired synthetic H2 epoch, never restart it."""
import json,os,pathlib
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as active
import nuc_unix_admin_h2_sdk_install as pkg
DONE=old.ETC/'unix-admin-h2-canary-expiry-inventory.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'inventory occupied')
 raw=old.read(active.DONE,0o600);epoch=json.loads(raw);require(epoch.get('boot_id')==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'boot changed')
 for name in (base.NET,base.SERVER,pkg.OLD,pkg.NEW):
  p=active.properties(name);require(p.get('Names')==name and p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','unit unresolved')
  cg=pathlib.Path('/sys/fs/cgroup/system.slice')/name
  if cg.exists():require((cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'cgroup populated')
 old.directory(base.DATA,2004,2004,0o700);st=base.DATA.stat();require(not os.path.lexists(base.DATA/'sfactory-unix-admin-h2'/'admin.sock'),'socket still present')
 names=('unix-admin-h2-canary-orchestration-started.json','unix-admin-h2-canary-orchestration-complete.json','unix-admin-h2-canary-sdk-old-start-started.json','unix-admin-h2-canary-sdk-new-start-started.json','unix-admin-h2-canary-register-old-started.json','unix-admin-h2-canary-ingress-probe-started.json')
 present={n:os.path.lexists(old.ETC/n) for n in names};require(present[names[0]] and not any(present[n] for n in names[1:]),'effect stage unknown')
 return {'schema':1,'epoch_sha256':base.sha(raw),'data_dev':st.st_dev,'data_ino':st.st_ino,'units_terminal':True,'admin_socket_absent':True,'effect_intents_absent':True,'scope':'read-only terminal inventory, no restart or cleanup'}
def apply(approved):
 require(plan()==approved,'inventory changed');old.store(DONE,base.canonical(approved)+b'\n',0o600);return approved
