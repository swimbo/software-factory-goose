"""One bounded restart of owned synthetic Restate; preserve fixture history."""
import errno,json,os,pathlib,stat,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_unix_admin_canary_sdk_v4_install as pkg
import nuc_unix_admin_canary_start_v4_old as epochcheck
START=old.ETC/'unix-admin-canary-restate-restart-started.json';DONE=old.ETC/'unix-admin-canary-restate-restart-complete.json'
PROBES={'journal':'sfactory-unix-admin-restart-journal-probe.service','control':'sfactory-unix-admin-restart-control-probe.service'}
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'restart already attempted')
 raw=old.read(old.ETC/'unix-admin-canary-epoch2-complete.json',0o600);epoch=json.loads(raw);epochcheck.verify_epoch(epoch);require(epoch['boot_id']==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'boot changed')
 retired=json.loads(old.read(old.ETC/'unix-admin-canary-v4-retirement-complete.json',0o600));require(retired.get('unit')==pkg.OLD and retired.get('restart_refused') is True and retired.get('listener_closed') is True,'retirement unavailable')
 after=json.loads(old.read(old.ETC/'unix-admin-canary-after-journal.json',0o600));require(after.get('epoch_sha256')==base.sha(raw) and after.get('classification')=={'forwarded':'retained-nonterminal','old_effect':'absent'},'post-retirement classification unavailable')
 prezero=json.loads(old.read(old.ETC/'unix-admin-canary-snapshot-prezero-complete.json',0o600));require(prezero.get('epoch_sha256')==base.sha(raw) and prezero.get('result')=={'schema':1,'operation':'new-uri-matches','ids':[]},'prezero unavailable')
 started=json.loads(old.read(old.ETC/'unix-admin-canary-v4-register-new-started.json',0o600));unknown=json.loads(old.read(old.ETC/'unix-admin-canary-v4-register-new-unknown.json',0o600));require(started.get('scope')=='one fixed synthetic POST, deliberately discard response; remain unknown' and unknown=={'schema':1,'stage':'response_unknown','one_dispatch':True,'no_retry':True},'single dispatch unavailable')
 reconcile=json.loads(old.read(old.ETC/'unix-admin-canary-snapshot-reconcile-complete.json',0o600));matches=reconcile.get('result',{}).get('ids');require(reconcile.get('epoch_sha256')==base.sha(raw) and reconcile.get('role')=='reconcile' and isinstance(matches,list) and len(matches)==1 and isinstance(matches[0],str) and matches[0].startswith('dp_'),'new deployment unresolved')
 new=json.loads(old.read(old.ETC/'unix-admin-canary-v4-new-start-complete.json',0o600));p=active.properties(pkg.NEW);require(p.get('ActiveState')=='active' and p.get('MainPID')==str(new['pid']) and p.get('Job','')=='' and old.ctl('show',pkg.NEW,'-p','InvocationID','--value')==new['invocation_id'],'new SDK unavailable')
 p=active.properties(pkg.OLD);require(p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and os.path.lexists(pkg.HANDSHAKE/'old.retired') and os.path.lexists(pkg.HANDSHAKE/'old.stopped'),'old SDK not fenced')
 for name,value in (('old.retired',b'retired\n'),('old.stopped',b'stopped\n')):
  fd=os.open(pkg.HANDSHAKE/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2000,1,0o440),'retirement marker unavailable');old.noacl(fd);require(os.read(fd,128)==value,'retirement marker changed')
  finally:os.close(fd)
 for name in PROBES.values():require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','restart probe occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in PROBES.values():
  stem=name.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
  for root in map(pathlib.Path,paths):
   for pth in [root/name,root/(name+'.d'),root/'service.d']+[root/(x+'.service.d') for x in prefixes]:require(not os.path.lexists(pth),'unit collision')
 return {'schema':1,'epoch2_sha256':base.sha(raw),'old_deployment_id':retired['deployment_id'],'new_deployment_id':matches[0],'net_pid':epoch['processes'][base.NET],'old_restate_pid':epoch['processes'][base.SERVER],'new_sdk_pid':new['pid'],'new_sdk_invocation_id':new['invocation_id'],'scope':'restart only owned disposable Restate; retain data and SDKs'}
def apply(approved):
 require(plan()==approved,'restart plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 before=json.loads(old.read(old.ETC/'unix-admin-canary-epoch2-complete.json',0o600));epochcheck.verify_epoch(before);require(old.ctl('show',pkg.NEW,'-p','InvocationID','--value')==approved['new_sdk_invocation_id'] and active.properties(pkg.NEW).get('MainPID')==str(approved['new_sdk_pid']),'new SDK changed')
 old.ctl('stop',base.SERVER);p=active.properties(base.SERVER);require(p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','Restate stop unknown')
 old.ctl('start',base.SERVER);p=active.properties(base.SERVER);pid=int(p.get('MainPID','0'));require(p.get('ActiveState')=='active' and pid>1 and p.get('Job','')=='' and p.get('User')=='sfgoose-journal' and p.get('NoNewPrivileges')=='yes' and p.get('CapabilityBoundingSet')=='' and p.get('JoinsNamespaceOf')==base.NET and p.get('ProtectSystem')=='strict' and str(base.DATA) in p.get('ReadWritePaths',''),'Restate restart unknown')
 status=(pathlib.Path('/proc')/str(pid)/'status').read_text();fields={k:v.split() for k,v in (x.split(':',1) for x in status.splitlines() if ':' in x)};require(fields.get('Uid')==['2004']*4 and fields.get('Gid')==['2004']*4 and fields.get('NoNewPrivs')==['1'] and all(fields.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')),'Restate credentials unavailable')
 end=time.monotonic()+60;path=base.DATA/'sfactory-unix-admin'/'admin.sock'
 while time.monotonic()<end and not os.path.lexists(path):time.sleep(.2)
 require(os.path.lexists(path),'admin unavailable');old.directory(base.DATA,2004,2004,0o700);old.directory(path.parent,2004,2004,0o700);s=os.lstat(path);require(stat.S_ISSOCK(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)==(2004,2004,0o700,1),'socket metadata unavailable')
 try:os.getxattr(path,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'socket ACL unavailable')
 else:raise RuntimeError('socket ACL forbidden')
 active.PROBES=PROBES;journal=active.role('journal');control=active.role('control');require(journal.get('admin_ok') is True and journal.get('tcp_denied') is True and control=={'tcp_denied':True,'unix_denied':True} and (journal.get('socket_dev'),journal.get('socket_ino'))==(s.st_dev,s.st_ino),'admin permissions unavailable')
 old.ctl('start',pkg.OLD);oldp=active.properties(pkg.OLD);require(old.ctl('show',pkg.OLD,'-p','ConditionResult','--value')=='no' and oldp.get('MainPID')=='0' and oldp.get('ActiveState') in ('inactive','failed'),'old restart not refused')
 require(active.properties(base.NET).get('MainPID')==str(approved['net_pid']) and active.properties(pkg.NEW).get('MainPID')==str(approved['new_sdk_pid']) and old.ctl('show',pkg.NEW,'-p','InvocationID','--value')==approved['new_sdk_invocation_id'] and active.properties(base.SERVER).get('MainPID')==str(pid),'fixture changed')
 prior=json.loads(old.read(old.ETC/'unix-admin-canary-epoch2-complete.json',0o600));net=prior['identities'][base.NET];netproc=(pathlib.Path('/proc')/str(approved['net_pid'])/'stat').read_text();netcg=(pathlib.Path('/sys/fs/cgroup/system.slice')/base.NET).stat();require(old.ctl('show',base.NET,'-p','InvocationID','--value')==net['invocation_id'] and int(netproc.rsplit(')',1)[1].split()[19])==net['start_ticks'] and (netcg.st_dev,netcg.st_ino)==(net['cgroup_dev'],net['cgroup_ino']),'namespace anchor changed')
 epoch=json.loads(old.read(old.ETC/'unix-admin-canary-epoch2-complete.json',0o600));inv=old.ctl('show',base.SERVER,'-p','InvocationID','--value');cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/base.SERVER).stat();proc=(pathlib.Path('/proc')/str(pid)/'stat').read_text();ticks=int(proc.rsplit(')',1)[1].split()[19]);epoch['processes'][base.SERVER]=pid;epoch['identities'][base.SERVER]={'pid':pid,'invocation_id':inv,'start_ticks':ticks,'cgroup_dev':cg.st_dev,'cgroup_ino':cg.st_ino};epoch['socket_dev']=s.st_dev;epoch['socket_ino']=s.st_ino;epoch['journal']=journal;epoch['control']=control;epoch['registration']=True
 result={'schema':1,'epoch2_sha256':approved['epoch2_sha256'],'old_deployment_id':approved['old_deployment_id'],'new_deployment_id':approved['new_deployment_id'],'old_restart_refused':True,'epoch3':epoch,'history_replayed':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
