"""Create-only SDK profile for the fresh, disposable H2 ingress fixture."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_sdk_v4_install as pinned
ROOT=pathlib.Path('/var/lib/software-factory-goose/unix-admin-h2-canary');HANDSHAKE=ROOT/'handshake'
NET='sfactory-unix-admin-h2-canary-net.service';OLD='sfactory-unix-admin-h2-canary-sdk-old.service';NEW='sfactory-unix-admin-h2-canary-sdk-new.service'
START=old.ETC/'unix-admin-h2-canary-sdk-install-started.json';DONE=old.ETC/'unix-admin-h2-canary-sdk-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def units():
 out={}
 for name,role in ((OLD,'old'),(NEW,'new')):
  log=HANDSHAKE/(role+'.log')
  text='''[Unit]\nDescription=Owned synthetic H2 SDK %s\nBindsTo=%s\nAfter=%s\nJoinsNamespaceOf=%s\n[Service]\nType=exec\nUser=sfgoose-control\nGroup=sfgoose-control\nPrivateNetwork=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nUMask=0077\nStandardInput=null\nStandardOutput=append:%s\nStandardError=append:%s\nLimitFSIZE=1M\nEnvironment=TOKIO_WORKER_THREADS=2\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestart=no\nMemoryMax=256M\nTasksMax=64\nCPUQuota=100%%\nRuntimeMaxSec=1200s\nExecStart=%s %s\n'''%(role,NET,NET,NET,log,log,pinned.BIN,role)
  if role=='old':text=text.replace('[Service]','ConditionPathExists=!'+str(HANDSHAKE/'old.retired')+'\n[Service]',1)
  out[name]=text.encode()
 return out
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (HANDSHAKE/'old.log',HANDSHAKE/'new.log',START,DONE)),'SDK profile occupied')
 old.directory(ROOT,0,0,0o711);old.directory(HANDSHAKE,0,2000,0o710);old.read(pinned.BIN,0o755,pinned.SHA,40_000_000)
 require(json.loads(old.read(pinned.DONE,0o600))=={'installed':True,'started':False,'registration':False},'SDK provenance unavailable')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in units():
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','unit occupied');stem=name.removesuffix('.service')
  for root in map(pathlib.Path,paths):
   for n in [name,name+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/n),'unit collision')
 return {'schema':1,'sdk_sha256':pinned.SHA,'units':{n:base.sha(v) for n,v in units().items()},'scope':'install only separate synthetic H2 SDK units'}
def apply(approved):
 require(plan()==approved,'SDK plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 for role in ('old','new'):
  fd=os.open(HANDSHAKE/(role+'.log'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  try:os.fchown(fd,0,2000);os.fchmod(fd,0o620);old.noacl(fd);os.fsync(fd)
  finally:os.close(fd)
 old.syncdir(HANDSHAKE)
 for name,data in units().items():old.store(old.UNIT/name,data,0o644)
 old.ctl('daemon-reload')
 for name in units():require(old.ctl('show',name,'-p','LoadState','--value')=='loaded' and old.ctl('show',name,'-p','ActiveState','--value')=='inactive','unit unavailable')
 result={'schema':1,'installed':True,'started':False,'registration':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
