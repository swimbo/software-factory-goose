"""Owned SDK-v3 UID2000 startup preflight; unknown retains intent/resources."""
import hashlib,json,os,pathlib,stat,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_unix_admin_canary_sdk_v4_install as package
SHA='3756d5cbe5f4bb3dfc4a735cc45b30cdff076f2d812ef3f57ea7bea2952dc611'
DIR=base.ROOT/'sdk-v4-preflight';BIN=package.BIN;LOG=DIR/'startup.log';UNIT='sfactory-unix-admin-sdk-v4-preflight.service';CHECK='sfactory-unix-admin-sdk-v4-preflight-connect.service'
CLOSED='sfactory-unix-admin-sdk-v4-preflight-closed.service';BAD='sfactory-unix-admin-sdk-v4-preflight-extra-fd.service'
START=old.ETC/'unix-admin-sdk-v4-preflight-started.json';DONE=old.ETC/'unix-admin-sdk-v4-preflight-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(x) for x in (DIR,START,DONE)),'preflight occupied');old.directory(base.ROOT,0,0,0o711)
 for name in (UNIT,CHECK,CLOSED,BAD):
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','unit occupied')
  paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=name.removesuffix('.service');prefix=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
  for parent in map(pathlib.Path,paths):
   for p in [parent/name,parent/(name+'.d'),parent/'service.d']+[parent/(x+'.service.d') for x in prefix]:require(not os.path.lexists(p),'unit collision')
 raw=old.read(old.ETC/'unix-admin-canary-epoch2-complete.json',0o600);epoch=json.loads(raw)
 require(set(epoch)=={'schema','boot_id','data_dev','data_ino','processes','identities','namespace','socket_dev','socket_ino','journal','control','fixture_retained_active','registration'} and epoch['schema']==1 and epoch['boot_id']==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() and epoch['fixture_retained_active'] is True and epoch['registration'] is False and set(epoch['processes'])=={base.NET,base.SERVER} and set(epoch['identities'])=={base.NET,base.SERVER} and set(epoch['namespace'])=={'dev','ino'},'epoch unavailable')
 data=os.lstat(base.DATA);require((data.st_dev,data.st_ino)==(epoch['data_dev'],epoch['data_ino']),'data changed')
 for name in (base.NET,base.SERVER):
  p=active.properties(name);require(p.get('ActiveState')=='active' and p.get('MainPID')==str(epoch['processes'][name]) and p.get('Job','')=='' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and p.get('NoNewPrivileges')=='yes' and p.get('CapabilityBoundingSet')=='' and p.get('PrivateNetwork')=='yes' and p.get('User')==('root' if name==base.NET else 'sfgoose-journal') and (name==base.NET or (p.get('JoinsNamespaceOf')==base.NET and p.get('BindsTo')==base.NET)),'epoch process changed')
  started=old.ctl('show',name,'-p','ExecMainStartTimestampMonotonic','--value');require(started.isdigit() and 0<=time.monotonic()-int(started)/1000000<1050,'epoch lifetime insufficient')
  ident=epoch['identities'][name];require(set(ident)=={'pid','invocation_id','start_ticks','cgroup_dev','cgroup_ino'} and ident['pid']==epoch['processes'][name] and old.ctl('show',name,'-p','InvocationID','--value')==ident['invocation_id'],'epoch invocation changed')
  cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/name).stat();proc=(pathlib.Path('/proc')/str(ident['pid'])/'stat').read_text();require(')' in proc and len(proc)<8192 and int(proc.rsplit(')',1)[1].split()[19])==ident['start_ticks'] and (cg.st_dev,cg.st_ino)==(ident['cgroup_dev'],ident['cgroup_ino']),'epoch process identity changed')
 sock=os.lstat(base.DATA/'sfactory-unix-admin'/'admin.sock');require(stat.S_ISSOCK(sock.st_mode) and (sock.st_dev,sock.st_ino)==(epoch['socket_dev'],epoch['socket_ino']),'admin socket changed')
 installed=json.loads(old.read(package.DONE,0o600));require(installed=={'installed':True,'started':False,'registration':False},'SDK package unavailable')
 source=old.read(BIN,0o755,SHA,40_000_000)
 return {'epoch_sha256':hashlib.sha256(raw).hexdigest(),'namespace':epoch['namespace'],'processes':epoch['processes'],'binary_sha256':SHA,'binary_size':len(source),'unit':UNIT,'check_unit':CHECK,'closed_unit':CLOSED,'bad_fd_unit':BAD,'scope':'one owned UID2000 pre-bind FD self-check and loopback listener, no registration'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 os.mkdir(DIR,0o700);os.chmod(DIR,0o710);os.chown(DIR,0,2000);old.directory(DIR,0,2000,0o710)
 require(len(old.read(BIN,0o755,SHA,40_000_000))==approved['binary_size'],'binary changed')
 fd=os.open(LOG,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:os.fchown(fd,0,2000);os.fchmod(fd,0o620);old.noacl(fd);os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(DIR);old.syncdir(base.ROOT)
 argv=['/usr/bin/systemd-run','--unit='+UNIT,'--quiet','--property=Type=exec','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=After='+base.NET,'--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=StandardInput=null','--property=StandardOutput=append:'+str(LOG),'--property=StandardError=append:'+str(LOG),'--property=LimitFSIZE=1M','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=256M','--property=TasksMax=64','--setenv=TOKIO_WORKER_THREADS=2','--property=RuntimeMaxSec=60s',str(BIN),'old']
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=20,check=False);require(p.returncode==0 and len(p.stdout)<4096 and len(p.stderr)<4096,'startup outcome unknown')
 code="""import os,socket,time
f=dict(x.split(':',1) for x in open('/proc/self/status') if ':' in x)
if (os.getuid(),os.geteuid(),os.getgid(),os.getegid())!=(2000,2000,2000,2000) or f.get('NoNewPrivs','').strip()!='1' or any(int(f['Cap'+n].strip(),16)!=0 for n in ('Inh','Prm','Eff','Bnd','Amb')):raise RuntimeError('identity unavailable')
end=time.monotonic()+15
while True:
 try:
  c=socket.create_connection(('127.0.0.1',9081),timeout=1);c.close();break
 except ConnectionRefusedError:
  if time.monotonic()>=end:raise
  time.sleep(.1)
print('READY')"""
 argv=['/usr/bin/systemd-run','--unit='+CHECK,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',code]
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and p.stdout==b'READY\n' and len(p.stderr)<4096,'listener readiness unknown')
 state=active.properties(UNIT);require(state.get('ActiveState')=='active' and int(state.get('MainPID','0'))>1 and state.get('User')=='sfgoose-control' and state.get('NoNewPrivileges')=='yes' and state.get('CapabilityBoundingSet')=='' and state.get('JoinsNamespaceOf')==base.NET,'SDK service identity unavailable')
 pid=int(state['MainPID']);raw=(pathlib.Path('/proc')/str(pid)/'status').read_text();status={k:v.split() for k,v in (x.split(':',1) for x in raw.splitlines() if ':' in x)};require(status.get('Uid')==['2000']*4 and status.get('Gid')==['2000']*4 and all(status.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')) and status.get('NoNewPrivs')==['1'],'SDK credentials unavailable')
 old.ctl('stop',UNIT);state=active.properties(UNIT);require(state.get('ActiveState') in ('inactive','failed') and state.get('MainPID')=='0' and state.get('Job','')=='' and state.get('ControlGroup','')=='','SDK stop unknown')
 require(old.ctl('show',CHECK,'-p','MainPID','--value')=='0' and old.ctl('show',CHECK,'-p','Job','--value')=='','probe still running')
 code="""import socket
s=socket.socket();s.settimeout(2)
try:s.connect(('127.0.0.1',9081))
except ConnectionRefusedError:pass
else:raise RuntimeError('listener still reachable')
finally:s.close()
for p in ('/proc/self/net/tcp','/proc/self/net/tcp6'):
 for line in open(p).read().splitlines()[1:]:
  f=line.split()
  if f[1].rsplit(':',1)[1].upper()=='2379' and f[3]=='0A':raise RuntimeError('listener alive')
print('CLOSED')"""
 argv=['/usr/bin/systemd-run','--unit='+CLOSED,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',code]
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and p.stdout==b'CLOSED\n' and len(p.stderr)<4096,'closed listener unknown')
 require(old.ctl('show',CLOSED,'-p','MainPID','--value')=='0' and old.ctl('show',CLOSED,'-p','Job','--value')=='','closed probe still running')
 # A separately started exact SDK receives one deliberately unexpected FD.
 # Only a prompt application error with the known synthetic marker passes.
 argv=['/usr/bin/systemd-run','--unit='+BAD,'--wait','--quiet','--property=Type=exec','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=After='+base.NET,'--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=StandardInput=null','--property=StandardOutput=append:'+str(LOG),'--property=StandardError=append:'+str(LOG),'--property=OpenFile=/dev/null:unexpected:read-only','--property=LimitFSIZE=1M','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=256M','--property=TasksMax=64','--setenv=TOKIO_WORKER_THREADS=2','--property=RuntimeMaxSec=10s',str(BIN),'old']
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=20,check=False)
 require(p.returncode!=0 and len(p.stdout)<4096 and len(p.stderr)<4096 and old.ctl('show',BAD,'-p','ExecMainCode','--value')=='1' and old.ctl('show',BAD,'-p','ExecMainStatus','--value')=='1' and old.ctl('show',BAD,'-p','MainPID','--value')=='0' and old.ctl('show',BAD,'-p','Job','--value')=='','extra FD refusal unknown')
 fd=os.open(LOG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);require(st.st_uid==0 and st.st_gid==2000 and st.st_nlink==1 and st.st_size<=1048576,'diagnostic log unavailable');old.noacl(fd);content=os.read(fd,1048577);require(b'unexpected inherited descriptor' in content,'extra FD cause unavailable')
 finally:os.close(fd)
 result={'sdk_started_uid2000_fdcheck_passed':True,'listener_ready':True,'owned_unit_stopped':True,'extra_fd_denied':True,'registration':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
