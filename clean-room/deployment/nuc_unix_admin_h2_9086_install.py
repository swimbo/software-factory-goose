"""Create-only distinct 9086 synthetic SDK; never start or register."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_canary_sdk_install as prior
SOURCE=pathlib.Path('/tmp/sfactory-sdk5-fdguard-20261030/sdk-9086');SHA='7c10961fd403fa0cf265d4fd68cf3dd40acb4b8f80dd841be160756fc26d7b4c'
BIN=old.PREFIX/'unix-admin-h2-canary-sdk-9086';UNIT='sfactory-unix-admin-h2-canary-sdk-9086.service';LOG=base.HANDSHAKE/'9086.log'
START=old.ETC/'unix-admin-h2-canary-sdk-9086-install-started.json';DONE=old.ETC/'unix-admin-h2-canary-sdk-9086-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def unit():
 return ('''[Unit]\nDescription=Owned synthetic H2 SDK 9086\nBindsTo=%s\nAfter=%s\nJoinsNamespaceOf=%s\n[Service]\nType=exec\nUser=sfgoose-control\nGroup=sfgoose-control\nPrivateNetwork=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nUMask=0077\nStandardInput=null\nStandardOutput=append:%s\nStandardError=append:%s\nLimitFSIZE=1M\nEnvironment=TOKIO_WORKER_THREADS=2\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestart=no\nMemoryMax=256M\nTasksMax=64\nCPUQuota=100%%\nRuntimeMaxSec=1200s\nExecStart=%s new\n'''%(base.NET,base.NET,base.NET,LOG,LOG,BIN)).encode()
def plan():
 require(os.geteuid()==0 and isinstance(SHA,str) and len(SHA)==64 and not any(os.path.lexists(p) for p in (BIN,LOG,START,DONE,old.UNIT/UNIT)),'fixture occupied')
 old.directory(base.ROOT,0,0,0o711);old.directory(base.HANDSHAKE,0,2000,0o710)
 require(os.path.lexists(base.HANDSHAKE/'old.retired') and os.path.lexists(base.HANDSHAKE/'old.stopped'),'old fence unavailable')
 require(json.loads(old.read(old.ETC/'unix-admin-h2-canary-register-new-unknown.json',0o600)).get('no_retry') is True,'9082 unknown unavailable')
 old.directory(SOURCE.parent,1000,1000,0o700);candidate=prior.candidate(SOURCE,SHA,0o700,40_000_000)
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied');roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for root in map(pathlib.Path,roots):
  for n in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/n),'unit collision')
 return {'schema':1,'candidate':candidate,'unit_sha256':base.sha(unit()),'scope':'create-only distinct synthetic 9086 SDK; retain 9082 unknown'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);require(prior.candidate(SOURCE,SHA,0o700,40_000_000,BIN)==approved['candidate'],'candidate changed');old.syncdir(BIN.parent)
 fd=os.open(LOG,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:os.fchown(fd,0,2000);os.fchmod(fd,0o620);old.noacl(fd);os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(LOG.parent);old.store(old.UNIT/UNIT,unit(),0o644);old.ctl('daemon-reload');require(old.ctl('show',UNIT,'-p','LoadState','--value')=='loaded' and old.ctl('show',UNIT,'-p','ActiveState','--value')=='inactive','unit unavailable')
 result={'schema':1,'installed':True,'started':False,'registration':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
