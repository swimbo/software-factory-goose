"""Read-only inventory after the bounded retained-work epoch ends."""
import json,os,pathlib,stat
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as active
import nuc_unix_admin_h2_sdk_install as sdk
import nuc_unix_admin_h2_9086_install as candidate
DONE=old.ETC/'unix-admin-h2-canary-epoch3-inventory.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'inventory occupied')
 er=old.read(old.ETC/'unix-admin-h2-canary-epoch2-complete.json',0o600);epoch=json.loads(er);require(epoch.get('boot_id')==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'boot changed')
 for name in (base.NET,base.SERVER,sdk.OLD,sdk.NEW,candidate.UNIT):
  p=active.properties(name);require(p.get('Names')==name and p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','unit unresolved')
  cg=pathlib.Path('/sys/fs/cgroup/system.slice')/name
  try:st=os.lstat(cg)
  except FileNotFoundError:continue
  require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'cgroup unavailable or populated')
 old.directory(base.DATA,2004,2004,0o700);st=base.DATA.stat();require((st.st_dev,st.st_ino)==(66306,19142983) and not os.path.lexists(base.DATA/'sfactory-unix-admin-h2'/'admin.sock'),'data or socket changed')
 for name,expected in (('old.retired',b'retired\n'),('old.stopped',b'stopped\n')):
  fd=os.open(base.HANDSHAKE/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   x=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(x.st_mode) and (x.st_uid,x.st_gid,x.st_nlink,stat.S_IMODE(x.st_mode))==(0,2000,1,0o440) and os.read(fd,32)==expected,'old fence invalid')
  finally:os.close(fd)
 unknown=old.read(old.ETC/'unix-admin-h2-canary-register-new-unknown.json',0o600);require(json.loads(unknown)=={'schema':1,'stage':'response_unknown','one_dispatch':True,'no_retry':True},'unknown receipt unavailable')
 journal=old.read(old.ETC/'unix-admin-h2-canary-after-journal.json',0o600);require(json.loads(journal).get('classification')=={'forwarded':'retained-nonterminal','old_effect':'absent'},'journal unavailable')
 require(not os.path.lexists(old.ETC/'unix-admin-h2-canary-9086-start-started.json'),'9086 attempted')
 return {'schema':1,'prior_epoch_sha256':base.sha(er),'unknown_sha256':base.sha(unknown),'postretire_sha256':base.sha(journal),'data_dev':st.st_dev,'data_ino':st.st_ino,'units_terminal':True,'admin_socket_absent':True,'9082_outcome':'unknown','9086_attempted':False,'scope':'read-only retained-data inventory; no restart'}
def apply(approved):
 require(plan()==approved,'inventory changed');old.store(DONE,base.canonical(approved)+b'\n',0o600);return approved
