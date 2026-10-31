"""One-shot start of the exact disposable old SDK, after bounded preflight."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_unix_admin_canary_sdk_v4_install as pkg
import nuc_unix_admin_canary_sdk_v4_preflight as pre
START=old.ETC/'unix-admin-canary-v4-old-started.json';DONE=old.ETC/'unix-admin-canary-v4-old-start-complete.json';CHECK='sfactory-unix-admin-canary-v4-old-ready.service'
def require(v,m):
 if not v:raise RuntimeError(m)
def verify_epoch(epoch,allow_registered=False):
 require(epoch.get('schema')==1 and epoch.get('fixture_retained_active') is True and (epoch.get('registration') is False or (allow_registered and epoch.get('registration') is True)),'epoch receipt unavailable')
 for unit in (base.NET,base.SERVER):
  binding=epoch['identities'][unit];pid=binding['pid'];p=active.properties(unit)
  require(p.get('ActiveState')=='active' and p.get('MainPID')==str(pid) and old.ctl('show',unit,'-p','InvocationID','--value')==binding['invocation_id'],'epoch service changed')
  raw=(pathlib.Path('/proc')/str(pid)/'stat').read_text();require(')' in raw and int(raw.rsplit(')',1)[1].split()[19])==binding['start_ticks'],'epoch process changed')
  cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/unit).stat();require((cg.st_dev,cg.st_ino)==(binding['cgroup_dev'],binding['cgroup_ino']),'epoch cgroup changed')
 path=base.DATA/'sfactory-unix-admin'/'admin.sock';s=os.lstat(path);require((s.st_dev,s.st_ino)==(epoch['socket_dev'],epoch['socket_ino']),'epoch socket changed')
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(x) for x in (START,DONE,pkg.HANDSHAKE/'old.retired',pkg.HANDSHAKE/'old.stopped')),'old start unavailable')
 preflight=json.loads(old.read(pre.DONE,0o600));require(preflight=={'sdk_started_uid2000_fdcheck_passed':True,'listener_ready':True,'owned_unit_stopped':True,'extra_fd_denied':True,'registration':False},'SDK preflight unavailable')
 receipt=json.loads(old.read(pkg.DONE,0o600));require(receipt=={'installed':True,'started':False,'registration':False},'SDK package unavailable')
 old.read(pkg.BIN,0o755,pkg.BIN_SHA,40_000_000);old.read(old.UNIT/pkg.OLD,0o644,pkg.sha(pkg.units()[pkg.OLD]));old.directory(pkg.HANDSHAKE,0,2000,0o710)
 p=active.properties(pkg.OLD);require(p.get('LoadState')=='loaded' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('Names')==pkg.OLD and p.get('FragmentPath')==str(old.UNIT/pkg.OLD) and p.get('DropInPaths','')=='','old unit unavailable')
 inv=json.loads(old.read(old.ETC/'unix-admin-canary-epoch2-complete.json',0o600));verify_epoch(inv);require(inv['boot_id']==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'boot changed')
 for name in (base.NET,base.SERVER):
  current=active.properties(name);require(current.get('ActiveState')=='active' and current.get('MainPID')==str(inv['processes'][name]),'fixture unavailable')
 require(old.ctl('show',CHECK,'-p','LoadState','--value')=='not-found','readiness unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=CHECK.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
 for parent in map(pathlib.Path,paths):
  for path in [parent/CHECK,parent/(CHECK+'.d'),parent/'service.d']+[parent/(x+'.service.d') for x in prefixes]:require(not os.path.lexists(path),'unit collision')
 return {'schema':1,'unit':pkg.OLD,'sdk_sha256':pkg.BIN_SHA,'unit_sha256':pkg.sha(pkg.units()[pkg.OLD]),'check_unit':CHECK,'net_pid':inv['processes'][base.NET],'restate_pid':inv['processes'][base.SERVER],'namespace':inv['namespace'],'admin_socket_ino':inv['socket_ino'],'scope':'start exact disposable old SDK only; no registration'}
def apply(approved):
 require(plan()==approved,'start plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);old.ctl('start',pkg.OLD)
 p=active.properties(pkg.OLD);pid=int(p.get('MainPID','0'));require(p.get('ActiveState')=='active' and pid>1 and p.get('Names')==pkg.OLD and p.get('Job','')=='' and p.get('User')=='sfgoose-control' and p.get('NoNewPrivileges')=='yes' and p.get('CapabilityBoundingSet')=='' and p.get('JoinsNamespaceOf')==base.NET and p.get('ControlGroup')=='/system.slice/'+pkg.OLD,'old SDK unavailable')
 status=(pathlib.Path('/proc')/str(pid)/'status').read_text();fields={k:v.split() for k,v in (x.split(':',1) for x in status.splitlines() if ':' in x)};require(fields.get('Uid')==['2000']*4 and fields.get('Gid')==['2000']*4 and all(fields.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')) and fields.get('NoNewPrivs')==['1'],'old credentials unavailable')
 code="import socket,time;end=time.monotonic()+15\nwhile True:\n try:c=socket.create_connection(('127.0.0.1',9081),timeout=1);c.close();break\n except ConnectionRefusedError:\n  if time.monotonic()>=end:raise\n  time.sleep(.1)\nprint('READY')"
 argv=['/usr/bin/systemd-run','--unit='+CHECK,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',code]
 r=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=30,check=False);require(r.returncode==0 and r.stdout==b'READY\n' and len(r.stderr)<4096,'old listener unavailable');require(old.ctl('show',CHECK,'-p','MainPID','--value')=='0' and old.ctl('show',CHECK,'-p','Job','--value')=='','readiness process unavailable')
 require(active.properties(pkg.OLD).get('MainPID')==str(pid),'old SDK changed');inv=old.ctl('show',pkg.OLD,'-p','InvocationID','--value');cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/pkg.OLD).stat()
 result={'schema':1,'unit':pkg.OLD,'pid':pid,'invocation_id':inv,'cgroup_dev':cg.st_dev,'cgroup_ino':cg.st_ino,'uid':2000,'caps_empty':True,'listener_ready':True,'registration':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
