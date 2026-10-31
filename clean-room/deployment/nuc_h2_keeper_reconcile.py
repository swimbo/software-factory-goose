"""Reconcile only the known native H2 control failure; do not repeat it."""
import hashlib,json,os,pathlib,stat
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_h2_keeper_fixture_install as fixture
import nuc_h2_keeper_fixture_activate as activation
import nuc_h2_keeper_control as control
START=old.ETC/'h2-keeper-reconcile-started.json';DONE=old.ETC/'h2-keeper-reconcile-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE) and os.path.lexists(control.START) and not os.path.lexists(control.DONE),'reconciliation unavailable')
 before=json.loads(old.read(control.START,0o600,maxsize=196608));epoch=json.loads(old.read(activation.DONE,0o600));require(before.get('epoch')==epoch and epoch.get('boot_id')==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'epoch mismatch')
 old.read(control.BIN,0o755,control.BIN_SHA,10_000_000);old.read(control.SCRIPT,0o755,control.SOURCE_SHA)
 fd=os.open(control.MARKER,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode),st.st_size)==(0,2000,1,0o440,8) and os.read(fd,9)==b'stopped\n','marker mismatch')
 finally:os.close(fd)
 raw=control.output();lines=raw.splitlines();require(len(lines)==2,'control log unknown')
 ready={'schema':1,'stage':'ready','same_h2_connection_reused':True,'extra_fd_denied':True,'mutation':False};closed={'schema':1,'stage':'closed','held_connection_denied':True,'new_connection_denied':True,'mutation':False};require([json.loads(x) for x in lines]==[ready,closed],'control result mismatch')
 for name in (fixture.SDK,control.UNIT):
  p=active.properties(name);require(p.get('Names')==name and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','unit not terminal')
  cg=pathlib.Path('/sys/fs/cgroup/system.slice')/name
  if cg.exists():require((cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'unit cgroup populated')
 require(old.ctl('show',control.UNIT,'-p','ExecMainStatus','--value')=='0' and old.ctl('show',control.UNIT,'-p','Result','--value')=='success','control outcome unknown')
 require(activation.identity(fixture.NET)==epoch['identities'][fixture.NET],'network identity changed')
 return {'schema':1,'epoch':epoch,'control_log_sha256':hashlib.sha256(raw).hexdigest(),'scope':'reconcile terminal control and stop only exact owned network; preserve original unknown'}
def apply(approved):
 require(plan()==approved,'reconciliation changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 require(activation.identity(fixture.NET)==approved['epoch']['identities'][fixture.NET],'network identity changed')
 old.ctl('stop',fixture.NET);p=active.properties(fixture.NET);require(p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','network stop unknown')
 cg=pathlib.Path('/sys/fs/cgroup/system.slice')/fixture.NET
 if cg.exists():require((cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'network cgroup populated')
 result={'schema':1,'initial_and_reuse':True,'held_and_new_denied':True,'extra_fd_denied':True,'control_terminal_success':True,'network_stopped':True,'original_attempt_retained':True,'mutation':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
