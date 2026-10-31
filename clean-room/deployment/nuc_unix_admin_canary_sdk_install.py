"""Create-only fixture SDKs, fixed control probe, and admin operation source."""
import hashlib,json,os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
SRC=pathlib.Path('/tmp/sfactory-ingress-sdk-20261030');BIN_SOURCE=SRC/'ingress-fence-sdk-v3.stripped';PROBE_SOURCE=SRC/'nuc_ingress_fence_probe.py'
BIN_SHA='3b9cc811fae791f35b7f6ebfdcb8c2e0f56dd3cdc20d6ff3a55bd98fae396bfd';PROBE_SHA='b9ef772fd3f590b6fec7c9eb62204fc9f1e9caaaec2e2dacf52c6abb8381214b'
OPS_SHA='144e6fc6be2baf1250eced3aae0c4f3fd816d1accce1590c9d81ea7804465e85';OPS_SOURCE=None
BIN=old.PREFIX/'unix-admin-canary-sdk';PROBE=old.PREFIX/'unix-admin-canary-ingress-probe.py';OPS=old.PREFIX/'unix-admin-canary-fixed-ops.py'
HANDSHAKE=base.ROOT/'handshake';START=old.ETC/'unix-admin-canary-sdk-install-started.json';DONE=old.ETC/'unix-admin-canary-sdk-install-complete.json'
OLD='sfactory-unix-admin-canary-sdk-old.service';NEW='sfactory-unix-admin-canary-sdk-new.service'
def require(v,m):
 if not v:raise RuntimeError(m)
def sha(v):return hashlib.sha256(v).hexdigest()
def units():
 out={}
 for name,role in ((OLD,'old'),(NEW,'new')):
  log=HANDSHAKE/('sdk-'+role+'.log')
  condition='ConditionPathExists=!'+str(HANDSHAKE/'old.retired')+'\n' if role=='old' else ''
  out[name]=('''[Unit]\nDescription=Owned disposable ingress fixture SDK\nBindsTo=%s\nAfter=%s\nJoinsNamespaceOf=%s\n%s[Service]\nType=exec\nUser=sfgoose-control\nGroup=sfgoose-control\nPrivateNetwork=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nUMask=0077\nStandardInput=null\nStandardOutput=append:%s\nStandardError=append:%s\nLimitFSIZE=1M\nEnvironment=TOKIO_WORKER_THREADS=2\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestart=no\nMemoryMax=256M\nTasksMax=64\nCPUQuota=100%%\nRuntimeMaxSec=1200s\nExecStart=%s %s\n'''%(base.NET,base.NET,base.NET,condition,log,log,BIN,role)).encode()
 return out
def candidate(path,digest,mode,limit,dest=None):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);out=None
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(1000,1000,1,mode) and 0<s.st_size<=limit,'candidate identity unavailable');old.noacl(fd);h=hashlib.sha256();total=0
  if dest is not None:out=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  while b:=os.read(fd,65536):
   total+=len(b);require(total<=s.st_size,'candidate grew');h.update(b)
   if out is not None:
    view=memoryview(b)
    while view:
     n=os.write(out,view);require(n>0,'short write');view=view[n:]
  require(total==s.st_size and h.hexdigest()==digest,'candidate changed')
  if out is not None:os.fchmod(out,0o755);os.fsync(out)
  return {'dev':s.st_dev,'ino':s.st_ino,'size':total,'sha256':digest}
 finally:
  if out is not None:os.close(out)
  os.close(fd)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(x) for x in (START,DONE,BIN,PROBE,OPS,HANDSHAKE)),'package destination occupied')
 require(isinstance(OPS_SOURCE,bytes) and sha(OPS_SOURCE)==OPS_SHA,'fixed ops source unavailable')
 old.directory(SRC,1000,1000,0o700);old.directory(base.ROOT,0,0,0o711);old.directory(base.DATA,2004,2004,0o700)
 receipt=json.loads(old.read(active.DONE,0o600));require(receipt.get('fixture_retained_active') is True and receipt.get('production_data_used') is False,'phase1 unavailable')
 services={}
 for name in (base.NET,base.SERVER):
  p=active.properties(name);pid=int(p.get('MainPID','0'));require(p.get('ActiveState')=='active' and pid>1 and p.get('Names')==name and p.get('Job','')=='' and p.get('DropInPaths','')=='','fixture unavailable');services[name]=pid
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in units():
  require(not os.path.lexists(old.UNIT/name) and old.ctl('show',name,'-p','LoadState','--value')=='not-found','SDK unit occupied');stem=name.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
  for parent in map(pathlib.Path,paths):
   for p in [parent/name,parent/(name+'.d'),parent/'service.d']+[parent/(x+'.service.d') for x in prefixes]:require(not os.path.lexists(p),'unit collision')
 return {'sdk':candidate(BIN_SOURCE,BIN_SHA,0o755,40_000_000),'probe':candidate(PROBE_SOURCE,PROBE_SHA,0o600,65536),'ops_sha256':OPS_SHA,'units':{n:sha(b) for n,b in units().items()},'services':services,'admin_socket_dev':receipt['journal']['socket_dev'],'admin_socket_ino':receipt['journal']['socket_ino'],'handshake_owner':[0,2000,0o710],'scope':'create-only fixture SDK and fixed sources; no start or registration'}
def apply(approved):
 require(plan()==approved,'package changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 require(candidate(BIN_SOURCE,BIN_SHA,0o755,40_000_000,BIN)==approved['sdk'],'SDK source identity changed')
 require(candidate(PROBE_SOURCE,PROBE_SHA,0o600,65536,PROBE)==approved['probe'],'probe source identity changed')
 old.syncdir(old.PREFIX);old.store(OPS,OPS_SOURCE,0o755)
 os.mkdir(HANDSHAKE,0o700);os.chmod(HANDSHAKE,0o710);os.chown(HANDSHAKE,0,2000);old.directory(HANDSHAKE,0,2000,0o710);old.syncdir(base.ROOT)
 for role in ('old','new'):
  fd=os.open(HANDSHAKE/('sdk-'+role+'.log'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  try:
   os.fchown(fd,0,2000);os.fchmod(fd,0o620);s=os.fstat(fd);require((s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2000,1,0o620),'log metadata unavailable');old.noacl(fd);os.fsync(fd)
  finally:os.close(fd)
 old.syncdir(HANDSHAKE)
 for name,data in units().items():old.store(old.UNIT/name,data,0o644)
 old.ctl('daemon-reload')
 for name in units():
  p=active.properties(name);require(p.get('LoadState')=='loaded' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and p.get('Job','')=='','SDK unit unavailable')
 result={'installed':True,'started':False,'registration':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
