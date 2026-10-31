"""Stop only the completed synthetic fixture; keep all data and receipts."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as active
import nuc_unix_admin_h2_sdk_install as pkg
import nuc_unix_admin_h2_sdk_start as epochcheck
START=old.ETC/'unix-admin-h2-canary-quiesce-started.json';DONE=old.ETC/'unix-admin-h2-canary-quiesce-complete.json';CHECK='sfactory-unix-admin-h2-canary-quiesce-listener.service'
def require(v,m):
 if not v:raise RuntimeError(m)
def live(name,pid,inv,dev,ino,start_ticks=None):
 p=active.properties(name);require(p.get('ActiveState')=='active' and p.get('MainPID')==str(pid) and p.get('Job','')=='' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and old.ctl('show',name,'-p','InvocationID','--value')==inv,'live unit identity changed')
 cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/name).stat();require((cg.st_dev,cg.st_ino)==(dev,ino),'live cgroup identity changed')
 if start_ticks is not None:
  raw=(pathlib.Path('/proc')/str(pid)/'stat').read_text();require(')' in raw and int(raw.rsplit(')',1)[1].split()[19])==start_ticks,'live process identity changed')
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'quiesce already attempted')
 final_raw=old.read(old.ETC/'unix-admin-h2-canary-after-restart-journal.json',0o600);final=json.loads(final_raw);require(final.get('schema')==1 and isinstance(final.get('classification'),dict),'final evidence unavailable')
 raw=old.read(old.ETC/'unix-admin-h2-canary-restate-restart-complete.json',0o600);restart=json.loads(raw);require(final.get('restart_sha256')==base.sha(raw) and restart.get('old_restart_refused') is True,'restart evidence changed');epoch=restart['epoch3'];epochcheck.verify_epoch(epoch,allow_registered=True)
 new=json.loads(old.read(old.ETC/'unix-admin-h2-canary-sdk-new-start-complete.json',0o600));p=active.properties(pkg.NEW);require(p.get('ActiveState')=='active' and p.get('MainPID')==str(new['identity']['pid']) and p.get('Job','')=='' and p.get('ControlGroup')=='/system.slice/'+pkg.NEW and old.ctl('show',pkg.NEW,'-p','InvocationID','--value')==new['identity']['invocation_id'],'new SDK identity unavailable')
 cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/pkg.NEW).stat();require((cg.st_dev,cg.st_ino)==(new['identity']['cgroup_dev'],new['identity']['cgroup_ino']),'new SDK cgroup changed')
 p=active.properties(pkg.OLD);require(p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and old.ctl('show',pkg.OLD,'-p','ConditionResult','--value')=='no','old retirement unavailable')
 require(old.ctl('show',CHECK,'-p','LoadState','--value')=='not-found','listener check unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=CHECK.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
 for root in map(pathlib.Path,paths):
  for pth in [root/CHECK,root/(CHECK+'.d'),root/'service.d']+[root/(x+'.service.d') for x in prefixes]:require(not os.path.lexists(pth),'unit collision')
 return {'schema':1,'final_sha256':base.sha(final_raw),'restart_sha256':base.sha(raw),'new_pid':new['identity']['pid'],'new_invocation_id':new['identity']['invocation_id'],'new_cgroup_dev':new['identity']['cgroup_dev'],'new_cgroup_ino':new['identity']['cgroup_ino'],'net':epoch['identities'][base.NET],'restate':epoch['identities'][base.SERVER],'scope':'stop exact owned synthetic units; retain data, work and receipts'}
def terminal(name,expected=None):
 p=active.properties(name);require(p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','unit termination unknown')
 path=pathlib.Path('/sys/fs/cgroup/system.slice')/name
 if path.exists():
  st=path.stat()
  if expected is not None:require((st.st_dev,st.st_ino)==expected,'cgroup identity changed')
  events=dict(x.split() for x in (path/'cgroup.events').read_text().splitlines());require(events.get('populated')=='0','cgroup populated')
def apply(approved):
 require(plan()==approved,'quiesce plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 live(pkg.NEW,approved['new_pid'],approved['new_invocation_id'],approved['new_cgroup_dev'],approved['new_cgroup_ino']);old.ctl('stop',pkg.NEW);terminal(pkg.NEW,(approved['new_cgroup_dev'],approved['new_cgroup_ino']))
 code="import socket\nfor port in (9081,9082):\n s=socket.socket();s.settimeout(2)\n try:s.connect(('127.0.0.1',port))\n except ConnectionRefusedError:pass\n else:raise RuntimeError('listener alive')\n finally:s.close()\nfor p in ('/proc/self/net/tcp','/proc/self/net/tcp6'):\n for line in open(p).read().splitlines()[1:]:\n  f=line.split()\n  if f[1].rsplit(':',1)[1].upper() in ('2379','237A') and f[3]=='0A':raise RuntimeError('listener alive')\nprint('CLOSED')"
 argv=['/usr/bin/systemd-run','--unit='+CHECK,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',code]
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and p.stdout==b'CLOSED\n' and len(p.stderr)<=4096,'listener closure unknown');require(old.ctl('show',CHECK,'-p','MainPID','--value')=='0' and old.ctl('show',CHECK,'-p','Job','--value')=='','probe still active')
 for name,key in ((base.SERVER,'restate'),(base.NET,'net')):
  b=approved[key];live(name,b['pid'],b['invocation_id'],b['cgroup_dev'],b['cgroup_ino'],b['start_ticks']);old.ctl('stop',name);terminal(name,(b['cgroup_dev'],b['cgroup_ino']))
  if name==base.SERVER:require(not os.path.lexists(base.DATA/'sfactory-unix-admin-h2'/'admin.sock'),'admin socket still present')
 terminal(pkg.OLD);old.directory(base.DATA,2004,2004,0o700)
 before=json.loads(old.read(base.START,0o600));require(old.old_snapshot()==before['old'],'existing factory changed')
 result={'schema':1,'sdk_listeners_closed':True,'admin_socket_absent':True,'owned_units_terminal':True,'fixture_data_retained':True,'old_work_retained':True,'production_changed':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
