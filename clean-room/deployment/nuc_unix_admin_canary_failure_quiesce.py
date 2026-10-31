"""Fail-closed stop of the owned failed synthetic attempt; preserve all state."""
import json,os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_unix_admin_canary_sdk_v4_install as pkg
import nuc_unix_admin_canary_start_v4_old as epochcheck
import nuc_unix_admin_canary_retire_old as retirement
START=old.ETC/'unix-admin-canary-failure-quiesce-started.json';DONE=old.ETC/'unix-admin-canary-failure-quiesce-complete.json';CHECK='sfactory-unix-admin-canary-failure-listener.service'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,retirement.FENCE,retirement.STOPPED)),'failure quiesce unavailable')
 require(os.path.lexists(old.ETC/'unix-admin-canary-orchestration-started.json') and not os.path.lexists(old.ETC/'unix-admin-canary-orchestration-complete.json') and os.path.lexists(old.ETC/'unix-admin-canary-ingress-probe-started.json') and not os.path.lexists(old.ETC/'unix-admin-canary-before-retirement.json'),'not exact failed stage')
 require(os.path.lexists(old.ETC/'unix-admin-canary-failure-inventory.json') and os.path.lexists(old.ETC/'unix-admin-canary-snapshot-failure-complete.json'),'diagnostic evidence unavailable')
 require(not any(os.path.lexists(old.ETC/name) for name in ('unix-admin-canary-v4-new-started.json','unix-admin-canary-v4-register-new-started.json')),'new SDK action attempted')
 old.read(old.UNIT/pkg.NEW,0o644,pkg.sha(pkg.units()[pkg.NEW]));new=active.properties(pkg.NEW);require(new.get('LoadState')=='loaded' and new.get('Names')==pkg.NEW and new.get('ActiveState') in ('inactive','failed') and new.get('MainPID')=='0' and new.get('Job','')=='' and new.get('ControlGroup','')=='','new SDK not terminal')
 probe=active.properties('sfactory-unix-admin-canary-ingress-probe.service');require(probe.get('LoadState')=='loaded' and probe.get('Names')=='sfactory-unix-admin-canary-ingress-probe.service' and probe.get('ActiveState')=='failed' and probe.get('MainPID')=='0' and probe.get('Job','')=='' and probe.get('ControlGroup','')=='','probe not terminal')
 cgpath=pathlib.Path('/sys/fs/cgroup/system.slice/sfactory-unix-admin-canary-ingress-probe.service')
 if cgpath.exists():require(dict(x.split() for x in (cgpath/'cgroup.events').read_text().splitlines()).get('populated')=='0','probe cgroup populated')
 epoch_raw=old.read(old.ETC/'unix-admin-canary-epoch2-complete.json',0o600);epoch=json.loads(epoch_raw);epochcheck.verify_epoch(epoch)
 diagnostic=json.loads(old.read(old.ETC/'unix-admin-canary-failure-inventory.json',0o600));snap=json.loads(old.read(old.ETC/'unix-admin-canary-snapshot-failure-complete.json',0o600,maxsize=196608));require(diagnostic.get('schema')==1 and diagnostic.get('epoch_sha256')==base.sha(epoch_raw) and diagnostic.get('unit')=='sfactory-unix-admin-canary-ingress-probe.service' and snap.get('schema')==1 and snap.get('role')=='failure' and snap.get('epoch_sha256')==base.sha(epoch_raw) and snap.get('result',{}).get('operation')=='snapshot','diagnostic bindings unavailable')
 before=json.loads(old.read(old.ETC/'unix-admin-canary-v4-old-start-complete.json',0o600));p=active.properties(pkg.OLD);require(p.get('ActiveState')=='active' and p.get('MainPID')==str(before['pid']) and p.get('Job','')=='' and old.ctl('show',pkg.OLD,'-p','InvocationID','--value')==before['invocation_id'],'old SDK identity unavailable')
 cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/pkg.OLD).stat();require((cg.st_dev,cg.st_ino)==(before['cgroup_dev'],before['cgroup_ino']),'old SDK cgroup changed')
 require(old.ctl('show',CHECK,'-p','LoadState','--value')=='not-found','check unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=CHECK.removesuffix('.service');prefix=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
 for parent in map(pathlib.Path,paths):
  for path in [parent/CHECK,parent/(CHECK+'.d'),parent/'service.d']+[parent/(x+'.service.d') for x in prefix]:require(not os.path.lexists(path),'unit collision')
 return {'schema':1,'epoch_sha256':base.sha(epoch_raw),'old_pid':before['pid'],'old_invocation':before['invocation_id'],'old_cgroup_dev':cg.st_dev,'old_cgroup_ino':cg.st_ino,'identities':epoch['identities'],'scope':'stop only failed owned fixture; preserve journal and unknown evidence'}
def terminal(name,identity):
 p=active.properties(name);require(p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','unit stop unknown')
 path=pathlib.Path('/sys/fs/cgroup/system.slice')/name
 if path.exists():
  s=path.stat();require((s.st_dev,s.st_ino)==(identity['cgroup_dev'],identity['cgroup_ino']),'cgroup identity changed');events=dict(x.split() for x in (path/'cgroup.events').read_text().splitlines());require(events.get('populated')=='0','cgroup populated')
def live(name,b):
 p=active.properties(name);require(p.get('ActiveState')=='active' and p.get('MainPID')==str(b['pid']) and p.get('Job','')=='' and old.ctl('show',name,'-p','InvocationID','--value')==b['invocation_id'],'unit identity changed')
 cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/name).stat();require((cg.st_dev,cg.st_ino)==(b['cgroup_dev'],b['cgroup_ino']),'unit cgroup changed')
 if 'start_ticks' in b:
  raw=(pathlib.Path('/proc')/str(b['pid'])/'stat').read_text();require(')' in raw and int(raw.rsplit(')',1)[1].split()[19])==b['start_ticks'],'unit process changed')
def apply(approved):
 require(plan()==approved,'quiesce plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);retirement.marker(retirement.FENCE,b'retired\n')
 old_identity={'pid':approved['old_pid'],'invocation_id':approved['old_invocation'],'cgroup_dev':approved['old_cgroup_dev'],'cgroup_ino':approved['old_cgroup_ino']};live(pkg.OLD,old_identity);old.ctl('stop',pkg.OLD);terminal(pkg.OLD,old_identity)
 code="import socket;s=socket.socket();s.settimeout(2)\ntry:s.connect(('127.0.0.1',9081))\nexcept ConnectionRefusedError:pass\nelse:raise RuntimeError('old listener alive')\nfinally:s.close()\nfor p in ('/proc/self/net/tcp','/proc/self/net/tcp6'):\n for line in open(p).read().splitlines()[1:]:\n  f=line.split()\n  if f[1].rsplit(':',1)[1].upper() in ('2379','237A') and f[3]=='0A':raise RuntimeError('SDK listener alive')\nprint('CLOSED')"
 argv=['/usr/bin/systemd-run','--unit='+CHECK,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',code]
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and p.stdout==b'CLOSED\n' and len(p.stderr)<=4096,'listener closure unknown');require(old.ctl('show',CHECK,'-p','MainPID','--value')=='0' and old.ctl('show',CHECK,'-p','Job','--value')=='','check process unresolved')
 for name in (base.SERVER,base.NET):live(name,approved['identities'][name]);old.ctl('stop',name);terminal(name,approved['identities'][name])
 require(not os.path.lexists(base.DATA/'sfactory-unix-admin'/'admin.sock'),'admin socket remains');old.directory(base.DATA,2004,2004,0o700)
 result={'schema':1,'owned_units_terminal':True,'sdk_listeners_closed':True,'admin_socket_absent':True,'fixture_data_retained':True,'outcome':'unknown','registration_retried':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
