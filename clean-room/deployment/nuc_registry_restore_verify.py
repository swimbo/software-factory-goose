"""One-shot isolated restore state comparison; retain unknown on any failure.

 This compares scoped state hashes, not invocation queues or all journal data;
 successful output is insufficient by itself to authorize cutover.
"""
import errno,os,pathlib,stat,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_offline_backup as backup
import nuc_registry_retirement_coordinator as retirement
import nuc_registry_restore_prepare as prepare
import nuc_registry_restore_history as history
T=backup.T
START=gate.ROOT/'history'/(T+'.restore-verification-started.json')
DONE=gate.ROOT/'history'/(T+'.restore-verification-complete.json')
TRANSPORT=gate.ROOT/'history'/(T+'.restore-verification-transport.json')
NSUNIT='sfactory-registry-restore-'+T.lower()+'-namespace.service'
PROBEUNIT='sfactory-registry-history-'+T.lower()+'-restore.service'
NSCODE="import json,os; assert (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2004,)*4; d=dict(x.split(':',1) for x in open('/proc/self/status') if ':' in x); assert d['NoNewPrivs'].strip()=='1' and all(d['Cap'+n].strip()=='0000000000000000' for n in ('Inh','Prm','Eff','Bnd','Amb')); s=os.stat('/proc/self/ns/net'); print(json.dumps({'dev':s.st_dev,'ino':s.st_ino},sort_keys=True,separators=(',',':')))"
def require(v,m):
 if not v:raise RuntimeError(m)
def identity(unit):
 p=retirement.observe(unit);require(p.get('ActiveState')=='active' and p.get('MainPID','').isdigit() and int(p['MainPID'])>1 and len(p.get('InvocationID',''))==32,'restore service unavailable')
 return p

def plan_locked():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,TRANSPORT)),'restore verification occupied')
 raw=old.read(prepare.DONE,0o600);r=gate._json(raw);pr=gate._json(old.read(prepare.START,0o600,maxsize=1000000));require(r.get('schema')==1 and r.get('transition_id')==T and r.get('plan_sha256')==backup.sha(backup.canonical(pr)) and r.get('started') is False and r.get('restore_verified') is False,'restore preparation unavailable')
 baseline=old.read(history.DONE,0o600,maxsize=4*1024*1024);base=gate._json(baseline);bplan=gate._json(old.read(backup.START,0o600,maxsize=1000000));require(base.get('transition_id')==T and backup.sha(baseline)==bplan['history_baseline_sha256'],'baseline changed')
 backup.retirement_state();retirement.terminal(backup.RESTATE,bplan['restate']);old.read(backup.FENCE,0o600,backup.sha(b'offline\n'));old.read(backup.DROP,0o644,backup.sha(backup.dropin()));backup.verify_loaded_fence(bplan['restate'])
 old.read(history.PROBE,0o755,history.PROBE_SHA,65536);old.read(prepare.CONF,0o644,backup.sha(prepare.CONFIG));old.directory(prepare.ROOT,0,0,0o711);old.directory(prepare.DATA,2004,2004,0o700)
 for name,body in prepare.units().items():
  old.read(old.UNIT/name,0o644,backup.sha(body));p=retirement.properties(name);require(p.get('LoadState')=='loaded' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('DropInPaths','')=='','restore unit unavailable')
 for unit in (NSUNIT,PROBEUNIT):history.unit_available(unit)
 return {'schema':1,'transition_id':T,'preparation_sha256':backup.sha(raw),'baseline_sha256':backup.sha(baseline),'preservation':bplan['preservation'],'targets':[{'service':x['service'],'key':x['key']} for x in base['histories']],'private_namespace':bplan['preservation']['private_namespace'],'host_namespace':bplan['preservation']['host_namespace'],'scope':'one isolated restore scoped state comparison and owned teardown'}
def plan():
 with backup.locked():return plan_locked()
def namespace():
 args=['/usr/bin/systemd-run','--unit='+NSUNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+prepare.NET,'--property=BindsTo='+prepare.NET,'--property=After='+prepare.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=32M','--property=TasksMax=8','--property=RuntimeMaxSec=10s','/usr/bin/python3','-I','-B','-c',NSCODE]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=20,check=False);require(p.returncode==0 and len(p.stdout)<=1024 and len(p.stderr)<=4096,'namespace observation unknown');obj=gate._json(p.stdout)
 require(isinstance(obj,dict) and set(obj)=={'dev','ino'} and all(type(obj[k]) is int and obj[k]>0 for k in ('dev','ino')) and old.ctl('show',NSUNIT,'-p','MainPID','--value')=='0' and old.ctl('show',NSUNIT,'-p','Job','--value')=='','namespace observation unavailable');return [obj['dev'],obj['ino']]
def apply(reviewed):
 with backup.locked():
  require(plan_locked()==reviewed,'restore verification plan changed');old.store(START,backup.canonical(reviewed),0o600);retirement.capture_transport(TRANSPORT,reviewed['preservation'])
  old.ctl('start',prepare.NET);net=identity(prepare.NET);old.ctl('start',prepare.SERVER);server=identity(prepare.SERVER)
  ns=namespace();require(ns!=reviewed['private_namespace'] and ns!=reviewed['host_namespace'],'restore namespace collision')
  path=prepare.DATA/'sfgoose-private'/'admin.sock';deadline=time.monotonic()+60
  while time.monotonic()<deadline and not os.path.lexists(path):time.sleep(.2)
  st=os.lstat(path);require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink)==(2004,2004,0o700,1),'restore socket unavailable')
  try:os.getxattr(path,'system.posix_acl_access',follow_symlinks=False)
  except OSError as e:require(e.errno==errno.ENODATA,'restore socket ACL unavailable')
  else:raise RuntimeError('restore socket ACL forbidden')
  result=history.invoke(PROBEUNIT,'restore',ns,prepare.NET,reviewed['targets']);base=gate._json(old.read(history.DONE,0o600,reviewed['baseline_sha256'],4*1024*1024));require(result['histories']==base['histories'],'restored state differs')
  for name,before in ((prepare.SERVER,server),(prepare.NET,net)):
   require(identity(name)==before,'restore unit identity changed');old.ctl('stop',name);retirement.terminal(name,before)
  require(not os.path.lexists(path),'restore admin socket remains');backup.retirement_state()
  receipt={'schema':1,'transition_id':T,'baseline_sha256':reviewed['baseline_sha256'],'scoped_state_match':True,'isolated_namespace':ns,'owned_units_terminal':True,'full_journal_verified':False,'promotion_authorized':False};old.store(DONE,backup.canonical(receipt),0o600);return receipt
