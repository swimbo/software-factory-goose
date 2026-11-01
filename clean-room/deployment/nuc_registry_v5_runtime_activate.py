"""Start guarded SDK5 with Unix listeners held behind its absent bootstrap marker."""
import os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_retirement_coordinator as retired
import nuc_registry_offline_backup as backup
import nuc_registry_v5_install as v5
import nuc_registry_v5_guarded_install as guarded
import nuc_registry_v5_unix_unit_upgrade as upgrade
import nuc_registry_unix_restate_activate as unix
import nuc_registry_v5_catalog_publish as catalog
import nuc_registry_sdk5_discovery_install as discovery
import nuc_registry_pinned_binary as pinned_binary
import nuc_sdk5_discovery_native_diagnostic3 as discovery_canary
import nuc_sdk5_discovery_native_canary as failed_canary
import nuc_sdk5_discovery_native_diagnostic2 as failed_diagnostic
import nuc_sdk5_stdio_shape_canary as stdio_shape
T=retired.T;START=gate.ROOT/'history'/(T+'.sdk5-activation-started.json');DONE=gate.ROOT/'history'/(T+'.sdk5-activation-complete.json');CHECK='sfactory-registry-v5-discovery-'+T.lower()+'.service'
SOCKETS=[v5.NAME+x+'.socket' for x in ('intake','worker','launch')];UNIT=v5.NAME+'runtime.service'
PATHS=[old.RUN/'registry-v5-intake.sock',old.RUN/'registry-v5-worker.sock',old.RUN/'registry-v5-launch-grant.sock']
def require(v,m):
 if not v:raise RuntimeError(m)
def validate_discovery_proofs(canary,shape):
 require(isinstance(canary,dict) and type(canary.get('schema')) is int and all(type(canary.get(k)) is bool for k in ('positive_discovery','inherited_connected_fd_denied','units_stopped','registration','production_changed')) and canary=={'schema':1,'probe_sha256':discovery.SOURCE_SHA,'server_sha256':discovery_canary.SERVER_SHA,'positive_discovery':True,'inherited_connected_fd_denied':True,'units_stopped':True,'registration':False,'production_changed':False} and discovery_canary.SERVER_SHA is not None,'native discovery proof unavailable')
 require(set(shape)=={'schema','inherited','devnull','production_access'} and type(shape['schema']) is int and shape['schema']==1 and shape['production_access'] is False and all(isinstance(shape.get(k),dict) and all(type(v) is bool for v in shape[k].values()) for k in ('inherited','devnull')) and shape['inherited']=={'character':True,'fifo':False,'readonly':False,'same_device_inode':False,'same_rdev':True} and shape['devnull']=={'character':True,'fifo':False,'readonly':False,'same_device_inode':True,'same_rdev':True},'native stdio proof unavailable')
def plan_locked():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,v5.MARKER,*PATHS)),'SDK5 activation occupied');retired_raw,_=backup.retirement_state()
 c=gate._json(old.read(catalog.DONE,0o600));require(c.get('transition_id')==T and c.get('gate_closed') is True and backup.sha(gate._protected_read(gate.REGISTRY,0o644,65536))==c.get('manifest_sha256'),'catalog unavailable')
 d=gate._json(old.read(discovery.DONE,0o600));require(d=={'schema':1,'sha256':discovery.SOURCE_SHA,'installed':True,'executed':False},'discovery probe unavailable');old.read(discovery.TARGET,0o755,discovery.SOURCE_SHA,10000000)
 canary=gate._json(old.read(discovery_canary.DONE,0o600));shape=gate._json(old.read(stdio_shape.DONE,0o600));validate_discovery_proofs(canary,shape)
 for failed in (failed_canary,failed_diagnostic):
  old.read(failed.START,0o600);require(not os.path.lexists(failed.DONE),'failed discovery history changed')
 u=gate._json(old.read(unix.DONE,0o600));require(u.get('transition_id')==T and u.get('gate_closed') is True and retired.observe(unix.provision.UNIT)==u['identity'],'Unix Restate unavailable')
 up=gate._json(old.read(upgrade.DONE,0o600));require(up.get('transition_id')==T and up.get('unit_sha256')==backup.sha(upgrade.unit()) and up.get('guarded_binary_sha256')==guarded.SOURCE_SHA and up.get('started') is False,'SDK5 unit upgrade unavailable');old.read(old.UNIT/UNIT,0o644,up['unit_sha256']);pinned_binary.verify(guarded.BIN,guarded.SOURCE_SHA)
 for name in SOCKETS:
  old.read(old.UNIT/name,0o644,backup.sha(v5.units()[name]));p=retired.properties(name);require(p.get('LoadState')=='loaded' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and p.get('ActiveState')=='inactive' and p.get('Job','')=='','SDK5 socket unavailable')
 p=retired.properties(UNIT);require(p.get('LoadState')=='loaded' and p.get('Names')==UNIT and p.get('FragmentPath')==str(old.UNIT/UNIT) and p.get('DropInPaths','')=='' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='','SDK5 runtime unavailable')
 require(old.ctl('show',CHECK,'-p','LoadState','--value')=='not-found','discovery unit occupied');roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable');stem=CHECK.removesuffix('.service')
 for parent in map(pathlib.Path,roots):
  for name in [CHECK,CHECK+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(parent/name),'discovery unit collision')
 return {'schema':1,'transition_id':T,'retirement_sha256':backup.sha(retired_raw),'manifest_sha256':c['manifest_sha256'],'unix_activation_sha256':backup.sha(old.read(unix.DONE,0o600)),'unit_sha256':up['unit_sha256'],'binary_sha256':guarded.SOURCE_SHA,'scope':'start guarded SDK only; bootstrap marker absent and gate closed'}
def plan():
 with backup.locked():return plan_locked()
def apply(approved):
 with backup.locked():
  require(plan_locked()==approved,'SDK5 activation changed');old.store(START,backup.canonical(approved),0o600)
  for name in SOCKETS:old.ctl('start',name)
  old.ctl('start',UNIT);p=retired.observe(UNIT);require(p.get('ActiveState')=='active' and int(p.get('MainPID','0'))>1 and p.get('Job','')=='' and p.get('fragment_sha256')==approved['unit_sha256'] and p.get('DropInPaths','')=='' and re.fullmatch(r'[0-9a-f]{32}',p.get('InvocationID','')) and p['InvocationID']!='0'*32,'SDK5 outcome unknown')
  for key,value in (('User','sfgoose-control'),('Group','sfgoose-control'),('PrivateNetwork','yes'),('NoNewPrivileges','yes'),('CapabilityBoundingSet','')):require(old.ctl('show',UNIT,'-p',key,'--value')==value,'SDK5 sandbox unavailable')
  fields={k:v.split() for k,v in (line.split(':',1) for line in pathlib.Path('/proc',p['MainPID'],'status').read_text().splitlines() if ':' in line)};require(fields.get('Uid')==['2000']*4 and fields.get('Gid')==['2000']*4 and fields.get('NoNewPrivs')==['1'] and all(fields.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')),'SDK5 credentials unavailable')
  for name,path,gid,mode in zip(SOCKETS,PATHS,(1000,2001,0),(0o660,0o660,0o600)):
   require(old.ctl('show',name,'-p','ActiveState','--value')=='active','SDK5 socket inactive');st=os.lstat(path);require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink)==(0,gid,mode,1),'SDK5 socket changed')
   try:os.getxattr(path,'system.posix_acl_access',follow_symlinks=False)
   except OSError as e:require(e.errno==old.errno.ENODATA,'socket ACL unavailable')
   else:raise RuntimeError('socket ACL forbidden')
  args=['/usr/bin/systemd-run','--unit='+CHECK,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+retired.attestation.ANCHOR_UNIT,'--property=BindsTo='+retired.attestation.ANCHOR_UNIT,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=StandardInput=null','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=30s',str(discovery.TARGET)]
  ready=subprocess.run(args,stdin=subprocess.DEVNULL,env=old.ENV,capture_output=True,timeout=40,check=False);require(ready.returncode==0 and ready.stdout==b'sdk5-discovery-verified\n' and len(ready.stderr)<=8192 and old.ctl('show',CHECK,'-p','MainPID','--value')=='0' and old.ctl('show',CHECK,'-p','Job','--value')=='','SDK5 discovery unavailable')
  require(not os.path.lexists(v5.MARKER) and retired.observe(UNIT)==p and backup.sha(gate._protected_read(gate.REGISTRY,0o644,65536))==approved['manifest_sha256'],'SDK5 scope changed')
  result={'schema':1,'transition_id':T,'identity':p,'manifest_sha256':approved['manifest_sha256'],'unix_activation_sha256':approved['unix_activation_sha256'],'bootstrap_marker_absent':True,'discovery_h2':True,'registered':False,'gate_closed':True};old.store(DONE,backup.canonical(result),0o600);return result
