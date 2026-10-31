"""One-shot owned Unix-admin permission proof. Unknown outcomes retain fixture."""
import errno,json,os,pathlib,stat,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as install
START=old.ETC/'unix-admin-canary-activation-started.json';DONE=old.ETC/'unix-admin-canary-activation-complete.json'
PROBES={'journal':'sfactory-unix-admin-canary-journal-probe.service','control':'sfactory-unix-admin-canary-control-probe.service'}
def require(v,m):
 if not v:raise RuntimeError(m)
def properties(unit):
 return dict(x.split('=',1) for x in old.ctl('show',unit,'--property=Id,Names,LoadState,ActiveState,MainPID,Job,FragmentPath,DropInPaths,Type,User,Group,PrivateNetwork,JoinsNamespaceOf,BindsTo,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ProtectSystem,ReadWritePaths,ProtectHome,PrivateTmp,UMask,Environment,MemoryMax,TasksMax,CPUQuotaPerSecUSec,ControlGroup,ExecStart','--all','--no-pager').splitlines())
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(x) for x in (START,DONE)),'activation already attempted')
 receipt=json.loads(old.read(install.DONE,0o600));before=json.loads(old.read(install.START,0o600));require(receipt=={'installed':True,'started':False,'network_changed':False,'production_data_used':False},'installation unavailable')
 require(install.verify_restate()==before['restate'],'restate binary changed');old.directory(install.ROOT,0,0,0o711);old.directory(install.DATA,2004,2004,0o700)
 for p,mode,digest in [(install.CONFIG,0o644,before['config_sha256']),(install.ANCHOR,0o755,before['anchor_sha256']),(install.PROBE,0o755,before['probe_sha256'])]:old.read(p,mode,digest)
 for name,raw in install.units().items():
  old.read(old.UNIT/name,0o644,install.sha(raw));p=properties(name);require(p.get('LoadState')=='loaded' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='','fixture unit changed')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in PROBES.values():
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','probe unit occupied');stem=name.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
  for base in map(pathlib.Path,paths):
   for p in [base/name,base/(name+'.d'),base/'service.d']+[base/(prefix+'.service.d') for prefix in prefixes]:require(not os.path.lexists(p),'probe unit collision')
 mem=dict(line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines());available=int(mem['MemAvailable'].split()[0])*1024;require(available>=4*1024**3,'insufficient host memory')
 require(old.old_snapshot()==before['old'],'existing factory changed')
 return {'installation':before,'probe_units':PROBES,'mem_available_at_least_bytes':4*1024**3,'scope':'start only fresh namespace and Restate; fixed native role probes; retain fixture on unknown'}
def role(role):
 name=PROBES[role];user={'journal':'sfgoose-journal','control':'sfgoose-control'}[role]
 args=['/usr/bin/systemd-run','--unit='+name,'--wait','--pipe','--quiet','--property=User='+user,'--property=Group='+user,'--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+install.NET,'--property=BindsTo='+install.NET,'--property=After='+install.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B',str(install.PROBE),role]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'probe failed or unknown');result=json.loads(p.stdout)
 require(old.ctl('show',name,'-p','MainPID','--value')=='0' and old.ctl('show',name,'-p','Job','--value')=='','probe not terminal');return result
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,install.canonical(approved)+b'\n',0o600)
 old.ctl('start',install.NET);old.ctl('start',install.SERVER)
 for name,user in [(install.NET,'root'),(install.SERVER,'sfgoose-journal')]:
  p=properties(name);require(p.get('LoadState')=='loaded' and p.get('ActiveState')=='active' and int(p.get('MainPID','0'))>1 and p.get('Job','')=='' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and p.get('Type')=='exec' and p.get('User')==user and p.get('PrivateNetwork')=='yes' and p.get('NoNewPrivileges')=='yes' and p.get('CapabilityBoundingSet')=='' and p.get('AmbientCapabilities','')=='','fixture service identity unavailable')
  if name==install.SERVER:require(p.get('JoinsNamespaceOf')==install.NET and p.get('BindsTo')==install.NET and p.get('ProtectSystem')=='strict' and str(install.DATA) in p.get('ReadWritePaths','') and p.get('ProtectHome')=='yes' and p.get('PrivateTmp')=='yes' and p.get('Environment')=='TOKIO_WORKER_THREADS=2','restate sandbox unavailable')
 end=time.monotonic()+60;path=install.DATA/'sfactory-unix-admin'/'admin.sock'
 while time.monotonic()<end and not os.path.lexists(path):time.sleep(.2)
 require(os.path.lexists(path),'admin socket unavailable')
 for directory in (pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib')):
  fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:s=os.fstat(fd);require(s.st_uid==0 and s.st_gid==0 and not s.st_mode&0o022,'unsafe ancestor');old.noacl(fd,True)
  finally:os.close(fd)
 old.directory(install.ROOT.parent,0,0,0o711);old.directory(install.ROOT,0,0,0o711);old.directory(install.DATA,2004,2004,0o700);old.directory(path.parent,2004,2004,0o700)
 sock=os.lstat(path);require(stat.S_ISSOCK(sock.st_mode) and (sock.st_uid,sock.st_gid,stat.S_IMODE(sock.st_mode),sock.st_nlink)==(2004,2004,0o700,1),'socket metadata unavailable')
 try:os.getxattr(path,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'socket ACL unavailable')
 else:raise RuntimeError('socket ACL forbidden')
 journal=role('journal');control=role('control')
 require((journal.get('socket_dev'),journal.get('socket_ino'),journal.get('socket_uid'),journal.get('socket_gid'),journal.get('socket_mode'))==(sock.st_dev,sock.st_ino,2004,2004,0o700),'socket changed')
 require(journal.get('tcp_denied') is True and journal.get('admin_ok') is True and control=={'tcp_denied':True,'unix_denied':True},'permission proof failed')
 require(old.old_snapshot()==approved['installation']['old'],'existing factory changed')
 result={'journal':journal,'control':control,'fixture_retained_active':True,'production_data_used':False};old.store(DONE,install.canonical(result)+b'\n',0o600);return result
