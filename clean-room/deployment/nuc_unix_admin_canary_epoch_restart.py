"""One-shot epoch 2 restart of owned Restate fixture; prior state retained."""
import errno,json,os,pathlib,re,stat,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_unix_admin_canary_epoch_inventory as inventory
START=old.ETC/'unix-admin-canary-epoch2-started.json';DONE=old.ETC/'unix-admin-canary-epoch2-complete.json'
PROBES={'journal':'sfactory-unix-admin-epoch2-journal-probe.service','control':'sfactory-unix-admin-epoch2-control-probe.service'}
NS='sfactory-unix-admin-epoch2-net-probe.service'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'epoch already attempted')
 before=json.loads(old.read(inventory.DONE,0o600));require(before['schema']==1 and before['boot_id']==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'terminal receipt changed')
 for name in before['units']:
  p=dict(x.split('=',1) for x in old.ctl('show',name,'--property=LoadState,ActiveState,MainPID,Job,ControlGroup','--all','--no-pager').splitlines())
  if p.get('LoadState')=='not-found':continue
  require(p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','fixture not terminal')
 old.directory(base.ROOT,0,0,0o711);old.directory(base.DATA,2004,2004,0o700);s=os.lstat(base.DATA);require((s.st_dev,s.st_ino)==(before['data_dev'],before['data_ino']),'data identity changed')
 original=json.loads(old.read(base.START,0o600));require(base.verify_restate()==original['restate'],'restate changed')
 for path,mode,digest in ((base.CONFIG,0o644,original['config_sha256']),(base.ANCHOR,0o755,original['anchor_sha256']),(base.PROBE,0o755,original['probe_sha256'])):old.read(path,mode,digest)
 for name,raw in base.units().items():old.read(old.UNIT/name,0o644,base.sha(raw))
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in (*PROBES.values(),NS):
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','probe unit occupied');stem=name.removesuffix('.service');prefix=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
  for root in map(pathlib.Path,paths):
   for p in [root/name,root/(name+'.d'),root/'service.d']+[root/(x+'.service.d') for x in prefix]:require(not os.path.lexists(p),'unit collision')
 mem=dict(x.split(':',1) for x in pathlib.Path('/proc/meminfo').read_text().splitlines());require(int(mem['MemAvailable'].split()[0])*1024>=4*1024**3,'memory unavailable');require(old.old_snapshot()==original['old'],'existing factory changed')
 return {'schema':1,'terminal_receipt_sha256':base.sha(old.read(inventory.DONE,0o600)),'boot_id':before['boot_id'],'data_dev':before['data_dev'],'data_ino':before['data_ino'],'probes':PROBES,'namespace_probe':NS,'scope':'one owned NET/Restate epoch restart; retain data and all prior receipts'}
def apply(approved):
 require(plan()==approved,'restart plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);old.ctl('start',base.NET);old.ctl('start',base.SERVER)
 processes={};identities={}
 for name,user in ((base.NET,'root'),(base.SERVER,'sfgoose-journal')):
  p=active.properties(name);pid=int(p.get('MainPID','0'));require(p.get('ActiveState')=='active' and pid>1 and p.get('Job','')=='' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and p.get('User')==user and p.get('PrivateNetwork')=='yes' and p.get('NoNewPrivileges')=='yes' and p.get('CapabilityBoundingSet')=='','service unavailable');processes[name]=pid
  uid=0 if name==base.NET else 2004;raw=(pathlib.Path('/proc')/str(pid)/'status').read_text();fields={k:v.split() for k,v in (x.split(':',1) for x in raw.splitlines() if ':' in x)};require(fields.get('Uid')==[str(uid)]*4 and fields.get('Gid')==[str(uid)]*4 and fields.get('NoNewPrivs')==['1'] and all(fields.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')),'process credentials unavailable')
  if name==base.SERVER:require(p.get('JoinsNamespaceOf')==base.NET and p.get('BindsTo')==base.NET and p.get('ProtectSystem')=='strict' and str(base.DATA) in p.get('ReadWritePaths','') and p.get('ProtectHome')=='yes' and p.get('PrivateTmp')=='yes' and p.get('Environment')=='TOKIO_WORKER_THREADS=2','server sandbox unavailable')
  inv=old.ctl('show',name,'-p','InvocationID','--value');require(re.fullmatch(r'[0-9a-f]{32}',inv) is not None,'invocation unavailable');cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/name).stat();proc=(pathlib.Path('/proc')/str(pid)/'stat').read_text();require(')' in proc and len(proc)<8192,'process stat unavailable');ticks=int(proc.rsplit(')',1)[1].split()[19]);identities[name]={'pid':pid,'invocation_id':inv,'start_ticks':ticks,'cgroup_dev':cg.st_dev,'cgroup_ino':cg.st_ino}
 end=time.monotonic()+60;path=base.DATA/'sfactory-unix-admin'/'admin.sock'
 while time.monotonic()<end and not os.path.lexists(path):time.sleep(.2)
 require(os.path.lexists(path),'admin socket unavailable');old.directory(base.ROOT.parent,0,0,0o711);old.directory(base.ROOT,0,0,0o711);old.directory(base.DATA,2004,2004,0o700);old.directory(path.parent,2004,2004,0o700)
 sock=os.lstat(path);require(stat.S_ISSOCK(sock.st_mode) and (sock.st_uid,sock.st_gid,stat.S_IMODE(sock.st_mode),sock.st_nlink)==(2004,2004,0o700,1),'socket unavailable')
 try:os.getxattr(path,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'socket ACL unavailable')
 else:raise RuntimeError('socket ACL forbidden')
 active.PROBES=PROBES;journal=active.role('journal');control=active.role('control');require(journal.get('admin_ok') is True and journal.get('tcp_denied') is True and control=={'tcp_denied':True,'unix_denied':True} and (journal.get('socket_dev'),journal.get('socket_ino'))==(sock.st_dev,sock.st_ino),'permission proof unavailable')
 code="import json,os\nif (os.getuid(),os.geteuid(),os.getgid(),os.getegid())!=(2004,2004,2004,2004):raise RuntimeError('identity')\ns=dict(x.split(':',1) for x in open('/proc/self/status').read().splitlines() if ':' in x)\nif s['NoNewPrivs'].strip()!='1' or not all(s['Cap'+n].strip()=='0000000000000000' for n in ('Inh','Prm','Eff','Bnd','Amb')):raise RuntimeError('capabilities')\nn=os.stat('/proc/self/ns/net');print(json.dumps({'dev':n.st_dev,'ino':n.st_ino}))"
 argv=['/usr/bin/systemd-run','--unit='+NS,'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',code]
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and len(p.stdout)<4096 and len(p.stderr)<4096,'namespace probe unknown');ns=json.loads(p.stdout);require(set(ns)=={'dev','ino'} and old.ctl('show',NS,'-p','MainPID','--value')=='0' and old.ctl('show',NS,'-p','Job','--value')=='','namespace probe unavailable')
 host=json.loads(old.read(old.RUN/'host-netns.json',0o600));private=json.loads(old.read(old.RUN/'private-netns.json',0o600));require((ns['dev'],ns['ino']) not in ((host['netns_dev'],host['netns_ino']),(private['netns_dev'],private['netns_ino'])),'namespace not isolated')
 for name,pid in processes.items():require(active.properties(name).get('MainPID')==str(pid) and old.ctl('show',name,'-p','InvocationID','--value')==identities[name]['invocation_id'],'process changed')
 original=json.loads(old.read(base.START,0o600));require(old.old_snapshot()==original['old'],'existing factory changed')
 result={'schema':1,'boot_id':approved['boot_id'],'data_dev':approved['data_dev'],'data_ino':approved['data_ino'],'processes':processes,'identities':identities,'namespace':ns,'socket_dev':sock.st_dev,'socket_ino':sock.st_ino,'journal':journal,'control':control,'fixture_retained_active':True,'registration':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
