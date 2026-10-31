"""Start exactly one fixed SDK role for the fresh synthetic H2 fixture."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as active
import nuc_unix_admin_h2_sdk_install as pkg
ROLE=None
def require(v,m):
 if not v:raise RuntimeError(m)
def verify_epoch(epoch,allow_registered=False):
 require(epoch.get('schema')==1 and epoch.get('fixture_retained_active') is True and epoch.get('production_data_used') is False and epoch.get('boot_id')==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'epoch unavailable')
 for unit in (base.NET,base.SERVER):require(active.identity(unit)==epoch['identities'][unit],'epoch changed')
 socket=base.DATA/'sfactory-unix-admin-h2'/'admin.sock';st=os.lstat(socket);journal=epoch['journal'];require((st.st_dev,st.st_ino)==(journal['socket_dev'],journal['socket_ino']),'socket changed')
def paths():
 require(ROLE in ('old','new'),'role unavailable');return (pkg.OLD if ROLE=='old' else pkg.NEW,old.ETC/('unix-admin-h2-canary-sdk-'+ROLE+'-start-started.json'),old.ETC/('unix-admin-h2-canary-sdk-'+ROLE+'-start-complete.json'),'sfactory-unix-admin-h2-sdk-'+ROLE+'-ready.service',9081 if ROLE=='old' else 9082)
def plan():
 name,start,done,check,port=paths();require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (start,done)),'start occupied')
 epoch=json.loads(old.read(active.DONE,0o600));require(epoch.get('fixture_retained_active') is True and epoch.get('production_data_used') is False and epoch.get('boot_id')==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'epoch unavailable')
 for unit in (base.NET,base.SERVER):require(active.identity(unit)==epoch['identities'][unit],'epoch changed')
 require(json.loads(old.read(pkg.DONE,0o600))=={'schema':1,'installed':True,'started':False,'registration':False},'SDK install unavailable');old.read(pkg.pinned.BIN,0o755,pkg.pinned.SHA,40_000_000);old.read(old.UNIT/name,0o644,base.sha(pkg.units()[name]));old.directory(pkg.HANDSHAKE,0,2000,0o710)
 require(not os.path.lexists(pkg.HANDSHAKE/'old.retired') or ROLE=='new','old SDK retired')
 if ROLE=='new':
  require(os.path.lexists(pkg.HANDSHAKE/'old.retired') and os.path.lexists(pkg.HANDSHAKE/'old.stopped'),'old retirement unavailable')
  prior=json.loads(old.read(old.ETC/'unix-admin-h2-canary-after-journal.json',0o600));require(prior.get('classification')=={'forwarded':'retained-nonterminal','old_effect':'absent'},'post-retirement journal unavailable')
 p=active.properties(name);require(p.get('LoadState')=='loaded' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='','SDK unit unavailable')
 require(old.ctl('show',check,'-p','LoadState','--value')=='not-found','check occupied')
 search_paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,check=True,timeout=10).stdout.decode().splitlines();require(search_paths,'unit paths unavailable');stem=check.removesuffix('.service')
 for root in map(pathlib.Path,search_paths):
  for n in [check,check+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/n),'unit collision')
 return {'schema':1,'role':ROLE,'unit':name,'port':port,'check_unit':check,'epoch_sha256':base.sha(old.read(active.DONE,0o600)),'unit_sha256':base.sha(pkg.units()[name])}
def apply(approved):
 require(plan()==approved,'start plan changed');name,start,done,check,port=paths();old.store(start,base.canonical(approved)+b'\n',0o600);old.ctl('start',name)
 p=active.properties(name);binding=active.identity(name);require(p.get('User')=='sfgoose-control' and p.get('Group')=='sfgoose-control' and p.get('PrivateNetwork')=='yes' and p.get('JoinsNamespaceOf')==base.NET and p.get('NoNewPrivileges')=='yes' and p.get('CapabilityBoundingSet')=='','SDK identity unavailable')
 status=(pathlib.Path('/proc')/str(binding['pid'])/'status').read_text();f={k:v.split() for k,v in (x.split(':',1) for x in status.splitlines() if ':' in x)};require(f.get('Uid')==['2000']*4 and f.get('Gid')==['2000']*4 and f.get('NoNewPrivs')==['1'] and all(f.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')),'SDK credentials unavailable')
 code="import socket,time;end=time.monotonic()+15\nwhile True:\n try:c=socket.create_connection(('127.0.0.1',%d),timeout=1);c.close();break\n except ConnectionRefusedError:\n  if time.monotonic()>=end:raise\n  time.sleep(.1)\nprint('READY')"%port
 args=['/usr/bin/systemd-run','--unit='+check,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',code]
 r=subprocess.run(args,env=old.ENV,capture_output=True,timeout=30,check=False);require(r.returncode==0 and r.stdout==b'READY\n' and len(r.stderr)<4096,'listener unavailable');require(old.ctl('show',check,'-p','MainPID','--value')=='0' and old.ctl('show',check,'-p','Job','--value')=='','readiness not terminal');require(active.identity(name)==binding,'SDK changed')
 result={'schema':1,'role':ROLE,'unit':name,'identity':binding,'uid':2000,'caps_empty':True,'listener_ready':True,'registration':False,'epoch_sha256':approved['epoch_sha256']};old.store(done,base.canonical(result)+b'\n',0o600);return result
