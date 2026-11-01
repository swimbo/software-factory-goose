"""One fixed UID2004 Unix-admin SDK5 registration; unknown is never retried."""
import errno,os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_retirement_coordinator as retired
import nuc_registry_offline_backup as backup
import nuc_registry_v5_transition_plan as trans
import nuc_registry_v5_runtime_activate as sdk
import nuc_registry_unix_restate_activate as unix
T=retired.T;SOURCE=None;SHA='db874583f821284c636f735352856a45c546c4a5fd0a48cb9ebe937e896311ac';HELPER=old.PREFIX/'registry-v5-unix-admin-fixed.py';UNIT='sfactory-registry-v5-unix-register-'+T.lower()+'.service';ZERO='sfactory-registry-v5-unix-prezero-'+T.lower()+'.service';INSTALL=gate.ROOT/'history'/(T+'.registration-helper-started.json');START=gate.ROOT/'history'/(T+'.registration-started.json');DONE=gate.ROOT/'history'/(T+'.registration-complete.json')
def require(v,m):
 if not v:raise RuntimeError(m)
def unit():
 return (f'[Unit]\nDescription=Fixed SDK5 one-shot Unix-admin registration\nBindsTo={retired.attestation.ANCHOR_UNIT}\nAfter={retired.attestation.ANCHOR_UNIT}\nJoinsNamespaceOf={retired.attestation.ANCHOR_UNIT}\n[Service]\nType=oneshot\nRemainAfterExit=yes\nUser=sfgoose-journal\nGroup=sfgoose-journal\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nStandardInput=null\nStandardOutput=journal\nStandardError=journal\nMemoryMax=64M\nTasksMax=16\nRuntimeMaxSec=30s\nExecStart=/usr/bin/python3 -I -B {HELPER} dispatch\n').encode()
def socket_bound():
 u=gate._json(old.read(unix.DONE,0o600));path=unix.backup.SOURCE/'sfgoose-private'/'admin.sock';st=os.lstat(path)
 require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(2004,2004,1,0o700) and (st.st_dev,st.st_ino)==(u['socket_dev'],u['socket_ino']),'admin socket changed')
 try:os.getxattr(path,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'socket ACL unavailable')
 else:raise RuntimeError('socket ACL forbidden')
def plan_locked():
 require(os.geteuid()==0 and isinstance(SOURCE,bytes) and backup.sha(SOURCE)==SHA and not any(os.path.lexists(p) for p in (HELPER,INSTALL,START,DONE,old.UNIT/UNIT)),'registration occupied')
 retired_raw,_=backup.retirement_state();planraw=old.read(trans.PLAN,0o600);p=gate._json(planraw);require(p.get('transition_id')==T and p.get('old_sdk_uri')=='http://127.0.0.1:9084' and p.get('new_sdk_uri')=='http://127.0.0.1:9085' and p.get('new_deployment_id') is None and backup.sha(gate._protected_read(gate.REGISTRY,0o644,65536))==p['new_manifest_sha256'],'transition plan unavailable')
 socket_bound();u=gate._json(old.read(unix.DONE,0o600));s=gate._json(old.read(sdk.DONE,0o600));require(retired.observe(unix.provision.UNIT)==u['identity'] and retired.observe(sdk.UNIT)==s['identity'] and s.get('bootstrap_marker_absent') is True and not os.path.lexists(sdk.v5.MARKER),'runtime scope changed')
 roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable')
 for name in (UNIT,ZERO):
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','registration unit occupied');stem=name.removesuffix('.service')
  for parent in map(pathlib.Path,roots):
   for n in [name,name+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(parent/n),'unit collision')
 return {'schema':1,'transition_id':T,'plan_sha256':backup.sha(planraw),'new_manifest_sha256':p['new_manifest_sha256'],'uri':'http://127.0.0.1:9085','retirement_sha256':backup.sha(retired_raw),'helper_sha256':SHA,'unit_sha256':backup.sha(unit()),'scope':'one fixed non-force SDK5 registration; no retries'}
def plan():
 with backup.locked():return plan_locked()
def apply(approved):
 with backup.locked():
  require(plan_locked()==approved,'registration plan changed');old.store(INSTALL,backup.canonical(approved),0o600);old.store(HELPER,SOURCE,0o755);old.store(old.UNIT/UNIT,unit(),0o644);old.ctl('daemon-reload');old.read(HELPER,0o755,SHA);old.read(old.UNIT/UNIT,0o644,approved['unit_sha256'])
  require(old.ctl('show',UNIT,'-p','Names','--value')==UNIT and old.ctl('show',UNIT,'-p','FragmentPath','--value')==str(old.UNIT/UNIT) and old.ctl('show',UNIT,'-p','DropInPaths','--value')=='' and old.ctl('show',UNIT,'-p','ActiveState','--value')=='inactive','registration unit changed')
  args=['/usr/bin/systemd-run','--unit='+ZERO,'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+retired.attestation.ANCHOR_UNIT,'--property=BindsTo='+retired.attestation.ANCHOR_UNIT,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B',str(HELPER),'prezero']
  p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096 and gate._json(p.stdout)=={'schema':1,'operation':'sdk5-prezero','matches':0} and old.ctl('show',ZERO,'-p','MainPID','--value')=='0' and old.ctl('show',ZERO,'-p','Job','--value')=='','SDK5 prezero unavailable')
  socket_bound();current,_=backup.retirement_state();require(backup.sha(current)==approved['retirement_sha256'],'retirement changed');require(retired.observe(unix.provision.UNIT)==gate._json(old.read(unix.DONE,0o600))['identity'] and retired.observe(sdk.UNIT)==gate._json(old.read(sdk.DONE,0o600))['identity'] and not os.path.lexists(sdk.v5.MARKER),'runtime changed');old.store(START,backup.canonical(approved),0o600);old.ctl('start',UNIT)
  fields={k:old.ctl('show',UNIT,'-p',k,'--value') for k in ('ActiveState','SubState','MainPID','Job','Result','ExecMainCode','ExecMainStatus','InvocationID')};inv=fields['InvocationID'];require(fields['ActiveState']=='active' and fields['SubState']=='exited' and fields['MainPID']=='0' and fields['Job']=='' and fields['Result']=='success' and fields['ExecMainCode']=='1' and fields['ExecMainStatus']=='0' and re.fullmatch(r'[0-9a-f]{32}',inv) and inv!='0'*32,'registration outcome unknown')
  log=subprocess.run(['/usr/bin/journalctl','--boot','--unit='+UNIT,'--no-pager','--output=cat','--lines=100','_SYSTEMD_INVOCATION_ID='+inv],env=old.ENV,capture_output=True,timeout=15,check=False);require(log.returncode==0 and len(log.stdout)<=8192 and len(log.stderr)<=4096,'registration journal unavailable');lines=log.stdout.splitlines();require(len(lines)==1,'registration response unavailable');out=gate._json(lines[0]);require(set(out)=={'schema','operation','deployment_id','uri','services'} and out.get('schema')==1 and out.get('operation')=='sdk5-registered' and out.get('uri')=='http://127.0.0.1:9085' and out.get('services')==['ClaimLeaseJournal','IntakeJournal','RuntimeIntakeJournal','WorkerQueueJournal'] and isinstance(out.get('deployment_id'),str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',out['deployment_id']),'registration metadata mismatch')
  socket_bound();current,_=backup.retirement_state();require(backup.sha(current)==approved['retirement_sha256'],'retirement changed');require(retired.observe(unix.provision.UNIT)==gate._json(old.read(unix.DONE,0o600))['identity'] and retired.observe(sdk.UNIT)==gate._json(old.read(sdk.DONE,0o600))['identity'],'runtime changed')
  result={'schema':1,'transition_id':T,'uri':approved['uri'],'deployment_id':out['deployment_id'],'invocation_id':inv,'binding_sha256':backup.sha(backup.canonical(approved))};old.store(DONE,backup.canonical(result),0o600);return result
