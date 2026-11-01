"""Prepare a separate isolated restore copy and inactive PID1 units only.

 No startup, admin access, journal execution or claim of restorability occurs.
 The separately reviewed activation must prove history and exact cleanup.
"""
import nuc_registry_pinned_binary as pinned_binary
import os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_offline_backup as backup
import nuc_registry_retirement_coordinator as retirement
import nuc_restate_backup_tree as tree
T=backup.T
ROOT=pathlib.Path('/var/lib/software-factory-goose')/('registry-transition-restore-'+T)
DATA=ROOT/'data'
CONF=old.ETC/('registry-restore-'+T+'.toml')
START=gate.ROOT/'history'/(T+'.restore-preparation-started.json')
DONE=gate.ROOT/'history'/(T+'.restore-preparation-complete.json')
TRANSPORT=gate.ROOT/'history'/(T+'.restore-preparation-transport.json')
NET='sfactory-registry-restore-'+T.lower()+'-net.service'
SERVER='sfactory-registry-restore-'+T.lower()+'-restate.service'
CONFIG=b'listen-mode = "tcp"\n[admin]\nlisten-mode = "unix"\n'
def require(v,m):
 if not v:raise RuntimeError(m)
def units():
 return {NET:('''[Unit]\nDescription=Isolated registry restore namespace\n[Service]\nType=exec\nUser=root\nGroup=root\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestart=no\nMemoryMax=64M\nTasksMax=16\nRuntimeMaxSec=900s\nExecStart=/usr/bin/sleep 900\n''').encode(),SERVER:('''[Unit]\nDescription=Isolated registry restore\nBindsTo=%s\nAfter=%s\nJoinsNamespaceOf=%s\n[Service]\nType=exec\nUser=sfgoose-journal\nGroup=sfgoose-journal\nPrivateNetwork=yes\nProtectSystem=strict\nReadWritePaths=%s\nProtectHome=yes\nPrivateTmp=yes\nUMask=0077\nEnvironment=TOKIO_WORKER_THREADS=2\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestart=no\nMemoryMax=2G\nTasksMax=128\nCPUQuota=100%%\nRuntimeMaxSec=900s\nExecStart=%s --config-file %s --base-dir %s --node-name sfgoose-private --bind-ip 127.0.0.1 --use-random-ports false --no-logo\n'''%(NET,NET,NET,DATA,backup.BINARY,CONF,DATA)).encode()}
def plan_locked():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (ROOT,CONF,START,DONE,TRANSPORT)),'restore preparation occupied')
 raw=old.read(backup.DONE,0o600,maxsize=65536);receipt=gate._json(raw)
 require(receipt.get('schema')==1 and receipt.get('transition_id')==T and receipt.get('restate_stopped') is True and receipt.get('restore_verified') is False,'offline backup unavailable')
 approved=gate._json(old.read(backup.START,0o600,maxsize=1000000));require(receipt.get('plan_sha256')==backup.sha(backup.canonical(approved)),'backup intent changed')
 backup.retirement_state();retirement.terminal(backup.RESTATE,approved['restate']);old.read(backup.FENCE,0o600,backup.sha(b'offline\n'));old.read(backup.DROP,0o644,backup.sha(backup.dropin()));backup.verify_loaded_fence(approved['restate'])
 pinned_binary.verify(backup.BINARY,backup.BINARY_SHA);old.directory(backup.DEST,0,0,0o700);old.directory(backup.DEST/'restate',2004,2004,0o700)
 manifest=old.read(backup.DEST/'manifest.json',0o600,receipt['backup_manifest_sha256'],tree.MAX_MANIFEST_BYTES)
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for unit in units():
  require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','restore unit occupied');stem=unit.removesuffix('.service')
  for parent in map(pathlib.Path,paths):
   for item in [parent/unit,parent/(unit+'.d'),parent/'service.d']+[parent/(stem[:i+1]+'.service.d') for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(item),'unit collision')
 return {'schema':1,'transition_id':T,'backup_receipt_sha256':backup.sha(raw),'preservation':approved['preservation'],'manifest_sha256':backup.sha(manifest),'config_sha256':backup.sha(CONFIG),'units':{name:backup.sha(data) for name,data in units().items()},'scope':'create isolated restore copy and inactive units only'}
def plan():
 with backup.locked():return plan_locked()
def apply(reviewed):
 with backup.locked():
  require(plan_locked()==reviewed,'restore plan changed');old.store(START,backup.canonical(reviewed),0o600);retirement.capture_transport(TRANSPORT,reviewed['preservation'])
  os.mkdir(ROOT,0o711);os.chmod(ROOT,0o711);old.syncdir(ROOT.parent);os.mkdir(DATA,0o700);os.chmod(DATA,0o700);os.chown(DATA,2004,2004);old.directory(DATA,2004,2004,0o700);old.syncdir(ROOT)
  src=os.open(backup.DEST/'restate',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);dst=os.open(DATA,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:manifest=tree.copy_tree(src,dst,2004,2004)
  finally:os.close(src);os.close(dst)
  require(backup.sha(backup.canonical(manifest))==reviewed['manifest_sha256'],'restore copy differs from backup')
  old.store(CONF,CONFIG,0o644)
  for name,body in units().items():old.store(old.UNIT/name,body,0o644)
  old.ctl('daemon-reload')
  for name,body in units().items():
   p=retirement.properties(name);require(p.get('LoadState')=='loaded' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='','restore unit unavailable');old.read(old.UNIT/name,0o644,backup.sha(body))
  backup.retirement_state();receipt={'schema':1,'transition_id':T,'plan_sha256':backup.sha(backup.canonical(reviewed)),'restore_copy_sha256':reviewed['manifest_sha256'],'started':False,'restore_verified':False};old.store(DONE,backup.canonical(receipt),0o600);return receipt
