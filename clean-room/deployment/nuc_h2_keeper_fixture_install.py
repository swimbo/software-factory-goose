"""Create-only isolated native H2 control fixture; does not start it."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_sdk_v4_install as sdk
ROOT=pathlib.Path('/var/lib/software-factory-goose/h2-keeper-canary')
HANDSHAKE=ROOT/'handshake';LOG=HANDSHAKE/'sdk.log'
NET='sfactory-h2-keeper-net.service';SDK='sfactory-h2-keeper-sdk.service'
START=old.ETC/'h2-keeper-canary-install-started.json';DONE=old.ETC/'h2-keeper-canary-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def units():
 net='''[Unit]\nDescription=Owned H2 keeper control network\n[Service]\nType=exec\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nMemoryMax=64M\nTasksMax=16\nCPUQuota=100%\nRuntimeMaxSec=1200s\nExecStart=/usr/bin/sleep 1200\n'''
 service='''[Unit]\nDescription=Owned H2 keeper control SDK\nBindsTo=%s\nAfter=%s\nJoinsNamespaceOf=%s\n[Service]\nType=exec\nUser=sfgoose-control\nGroup=sfgoose-control\nPrivateNetwork=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nUMask=0077\nStandardInput=null\nStandardOutput=append:%s\nStandardError=append:%s\nLimitFSIZE=1M\nEnvironment=TOKIO_WORKER_THREADS=2\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestart=no\nMemoryMax=256M\nTasksMax=64\nCPUQuota=100%%\nRuntimeMaxSec=1200s\nExecStart=%s old\n'''%(NET,NET,NET,LOG,LOG,sdk.BIN)
 return {NET:net.encode(),SDK:service.encode()}
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (ROOT,START,DONE)),'fixture occupied')
 old.directory(ROOT.parent,0,0,0o711);old.read(sdk.BIN,0o755,sdk.SHA,40_000_000)
 require(json.loads(old.read(sdk.DONE,0o600))=={'installed':True,'started':False,'registration':False},'SDK provenance unavailable')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,check=True,timeout=10).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in units():
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','unit occupied');stem=name.removesuffix('.service');prefix=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
  for root in map(pathlib.Path,paths):
   for path in [root/name,root/(name+'.d'),root/'service.d']+[root/(p+'.service.d') for p in prefix]:require(not os.path.lexists(path),'unit collision')
 return {'schema':1,'binary_sha256':sdk.SHA,'units':{name:base.sha(data) for name,data in units().items()},'root':str(ROOT),'scope':'create-only native H2 fixture; no start, Restate, registration or provider'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 os.mkdir(ROOT,0o711);os.chmod(ROOT,0o711);old.syncdir(ROOT.parent)
 os.mkdir(HANDSHAKE,0o710);os.chown(HANDSHAKE,0,2000);os.chmod(HANDSHAKE,0o710)
 fd=os.open(LOG,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:os.fchown(fd,0,2000);os.fchmod(fd,0o620);old.noacl(fd);os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(HANDSHAKE);old.syncdir(ROOT)
 for name,data in units().items():old.store(old.UNIT/name,data,0o644)
 old.ctl('daemon-reload')
 for name in units():require(old.ctl('show',name,'-p','LoadState','--value')=='loaded' and old.ctl('show',name,'-p','ActiveState','--value')=='inactive','unit unavailable')
 result={'schema':1,'installed':True,'started':False,'registration':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
