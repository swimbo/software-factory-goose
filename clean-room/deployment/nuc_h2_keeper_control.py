"""One-shot, owned H2 keeper control. No Restate, registration or provider."""
import json,os,pathlib,re,stat,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_h2_keeper_fixture_install as fixture
import nuc_h2_keeper_fixture_activate as activation
SOURCE=None
SOURCE_SHA='959c6af249b648b0a8e5facea772b78246885dd9c9ce0974bec8bad5aee2a0d3'
BIN_SOURCE=pathlib.Path('/tmp/sfactory-h2-keeper-20261030/keeper.stripped')
BIN_SHA='d098a8d0f04c281efebcef52addf39520d76cc1bdf88947ffc2fc9dc02ad9188'
BIN=old.PREFIX/'unix-admin-canary-h2-keeper';SCRIPT=fixture.ROOT/'control.py';LOG=fixture.HANDSHAKE/'control.log';MARKER=fixture.HANDSHAKE/'sdk.stopped'
UNIT='sfactory-h2-keeper-control.service';CHECK='sfactory-h2-keeper-listener-check.service';START=old.ETC/'h2-keeper-control-started.json';DONE=old.ETC/'h2-keeper-control-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def binary(dest=None):
 previous=(old.SOURCE,old.SOURCE_SHA)
 try:
  old.SOURCE=BIN_SOURCE;old.SOURCE_SHA=BIN_SHA;return old.binary(dest)
 finally:old.SOURCE,old.SOURCE_SHA=previous
def plan():
 require(os.geteuid()==0 and isinstance(SOURCE,bytes) and base.sha(SOURCE)==SOURCE_SHA,'control source unavailable')
 require(not any(os.path.lexists(x) for x in (BIN,SCRIPT,LOG,MARKER,START,DONE)),'control occupied')
 epoch=json.loads(old.read(activation.DONE,0o600));require(epoch.get('schema')==1 and epoch.get('boot_id')==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() and epoch.get('registration') is False and epoch.get('fixture_retained_active') is True,'epoch unavailable')
 for name in (fixture.NET,fixture.SDK):
  require(activation.identity(name)==epoch['identities'][name],'unit identity changed')
  p=active.properties(name);require(p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and p.get('NoNewPrivileges')=='yes' and p.get('CapabilityBoundingSet')=='' and p.get('PrivateNetwork')=='yes','unit configuration changed')
  old.read(old.UNIT/name,0o644,base.sha(fixture.units()[name]))
 old.directory(fixture.ROOT,0,0,0o711);old.directory(fixture.HANDSHAKE,0,2000,0o710)
 require(all(old.ctl('show',name,'-p','LoadState','--value')=='not-found' for name in (UNIT,CHECK)),'control unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for name in (UNIT,CHECK):
  stem=name.removesuffix('.service')
  for root in map(pathlib.Path,paths):
   for n in [name,name+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/n),'unit collision')
 return {'schema':1,'epoch':epoch,'binary':binary(),'source_sha256':SOURCE_SHA,'unit':UNIT,'scope':'single owned native H2 connection and inherited-fd control; no journal'}
def output():
 fd=os.open(LOG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2000,1,0o620) and s.st_size<=4096,'log unavailable');return os.read(fd,4097)
 finally:os.close(fd)
def wait_for(stage):
 until=time.monotonic()+30
 while time.monotonic()<until:
  raw=output();lines=raw.splitlines()
  if len(lines)>=stage:return [json.loads(x) for x in lines]
  time.sleep(.1)
 raise RuntimeError('control outcome unknown')
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 require(binary(BIN)==approved['binary'],'binary changed');old.syncdir(BIN.parent);old.read(BIN,0o755,BIN_SHA,10_000_000)
 old.store(SCRIPT,SOURCE,0o755);old.read(SCRIPT,0o755,SOURCE_SHA)
 fd=os.open(LOG,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:os.fchown(fd,0,2000);os.fchmod(fd,0o620);old.noacl(fd);os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(LOG.parent)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--quiet','--property=Type=exec','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+fixture.NET,'--property=BindsTo='+fixture.NET,'--property=After='+fixture.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=120s','--property=StandardInput=null','--property=StandardOutput=append:'+str(LOG),'--property=StandardError=append:'+str(LOG),'/usr/bin/python3','-I','-B',str(SCRIPT)]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=20,check=False);require(p.returncode==0,'control launch unknown')
 expected={'schema':1,'stage':'ready','same_h2_connection_reused':True,'extra_fd_denied':True,'mutation':False};require(wait_for(1)==[expected],'ready proof unavailable')
 state=activation.identity(UNIT);p=active.properties(UNIT);require(p.get('User')=='sfgoose-control' and p.get('Group')=='sfgoose-control' and p.get('PrivateNetwork')=='yes' and p.get('JoinsNamespaceOf')==fixture.NET and p.get('NoNewPrivileges')=='yes' and p.get('CapabilityBoundingSet')=='','control identity unavailable')
 require(activation.identity(fixture.SDK)==approved['epoch']['identities'][fixture.SDK] and activation.identity(fixture.NET)==approved['epoch']['identities'][fixture.NET],'fixture changed')
 old.ctl('stop',fixture.SDK);p=active.properties(fixture.SDK);require(p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='','SDK stop unknown')
 cg=pathlib.Path('/sys/fs/cgroup/system.slice')/fixture.SDK
 if cg.exists():
  st=cg.stat();i=approved['epoch']['identities'][fixture.SDK];require((st.st_dev,st.st_ino)==(i['cgroup_dev'],i['cgroup_ino']) and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'SDK cgroup not empty')
 code="import socket; s=socket.socket(); s.settimeout(2); r=s.connect_ex(('127.0.0.1',9081)); s.close(); raise SystemExit(0 if r==111 else 1)"
 args=['/usr/bin/systemd-run','--unit='+CHECK,'--quiet','--wait','--pipe','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+fixture.NET,'--property=BindsTo='+fixture.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=8','--property=RuntimeMaxSec=10s','/usr/bin/python3','-I','-B','-c',code]
 probe=subprocess.run(args,env=old.ENV,capture_output=True,timeout=20,check=False);require(probe.returncode==0 and len(probe.stdout)==0 and len(probe.stderr)<=4096,'listener refusal unknown')
 require(activation.identity(fixture.NET)==approved['epoch']['identities'][fixture.NET] and activation.identity(UNIT)==state,'identity changed')
 fd=os.open(MARKER,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:os.fchown(fd,0,2000);os.fchmod(fd,0o440);old.noacl(fd);os.write(fd,b'stopped\n');os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(MARKER.parent)
 closed={'schema':1,'stage':'closed','held_connection_denied':True,'new_connection_denied':True,'mutation':False};require(wait_for(2)==[expected,closed],'closed proof unavailable')
 until=time.monotonic()+10
 while time.monotonic()<until:
  p=active.properties(UNIT)
  if p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='':break
  time.sleep(.1)
 require(p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='' and old.ctl('show',UNIT,'-p','ExecMainStatus','--value')=='0','control termination unknown')
 old.ctl('stop',fixture.NET);p=active.properties(fixture.NET);require(p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='','network stop unknown')
 result={'schema':1,'initial_and_reuse':True,'held_and_new_denied':True,'extra_fd_denied':True,'mutation':False,'network_stopped':True};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
