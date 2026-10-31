"""One-shot root supervised synthetic registration; unknown stays attempted."""
import json,os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as active
import nuc_unix_admin_h2_sdk_install as pkg
import nuc_unix_admin_h2_helpers_install as helpers
ROLE=None
UNITS={'old':'sfactory-unix-admin-h2-canary-register-old.service','new':'sfactory-unix-admin-h2-canary-register-new.service'}
def require(v,m):
 if not v:raise RuntimeError(m)
def records(role):
 return (old.ETC/('unix-admin-h2-canary-register-'+role+'-started.json'),old.ETC/('unix-admin-h2-canary-register-'+role+'-complete.json'))
def verify_epoch(epoch):
 require(epoch.get('schema')==1 and epoch.get('fixture_retained_active') is True and epoch.get('production_data_used') is False,'epoch unavailable')
 for unit in (base.NET,base.SERVER):require(active.identity(unit)==epoch['identities'][unit],'epoch changed')
 socket=base.DATA/'sfactory-unix-admin-h2'/'admin.sock';st=os.lstat(socket);require((st.st_dev,st.st_ino)==(epoch['journal']['socket_dev'],epoch['journal']['socket_ino']),'socket changed')
def plan():
 role=ROLE;require(os.geteuid()==0 and role in UNITS,'role unavailable');started,complete=records(role);require(not os.path.lexists(started) and not os.path.lexists(complete),'registration already attempted')
 receipt=json.loads(old.read(pkg.DONE,0o600));require(receipt=={'schema':1,'installed':True,'started':False,'registration':False},'SDK package unavailable')
 old.read(helpers.ADMIN,0o755,helpers.ADMIN_SHA);old.read(pkg.pinned.BIN,0o755,pkg.pinned.SHA,40_000_000);sdk=pkg.OLD if role=='old' else pkg.NEW;old.read(old.UNIT/sdk,0o644,base.sha(pkg.units()[sdk]));p=active.properties(sdk);require(p.get('ActiveState')=='active' and int(p.get('MainPID','0'))>1 and p.get('Names')==sdk and p.get('Job','')=='' and p.get('FragmentPath')==str(old.UNIT/sdk) and p.get('DropInPaths','')=='' and p.get('User')=='sfgoose-control' and p.get('NoNewPrivileges')=='yes' and p.get('CapabilityBoundingSet')=='','SDK service unavailable')
 status=(pathlib.Path('/proc')/p['MainPID']/'status').read_text();fields={k:v.split() for k,v in (x.split(':',1) for x in status.splitlines() if ':' in x)};require(fields.get('Uid')==['2000']*4 and fields.get('Gid')==['2000']*4 and all(fields.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')) and fields.get('NoNewPrivs')==['1'],'SDK process identity unavailable')
 inventory=json.loads(old.read(old.ETC/'unix-admin-h2-canary-activation-complete.json',0o600));verify_epoch(inventory);require(inventory['boot_id']==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'fixture boot changed')
 for name in (base.NET,base.SERVER):
  current=active.properties(name);require(current.get('ActiveState')=='active' and current.get('MainPID')==str(inventory['identities'][name]['pid']),'fixture unavailable')
 unit=UNITS[role];require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','registration unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=unit.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
 for parent in map(pathlib.Path,paths):
  for pth in [parent/unit,parent/(unit+'.d'),parent/'service.d']+[parent/(x+'.service.d') for x in prefixes]:require(not os.path.lexists(pth),'unit collision')
 if role=='old':
  require(not os.path.lexists(pkg.HANDSHAKE/'old.retired'),'old retired')
  zero=json.loads(old.read(old.ETC/'unix-admin-h2-canary-snapshot-prezero-old-complete.json',0o600));require(zero.get('schema')==1 and zero.get('role')=='prezero-old' and zero.get('epoch_sha256')==base.sha(old.read(old.ETC/'unix-admin-h2-canary-activation-complete.json',0o600)) and zero.get('result')=={'schema':1,'operation':'old-uri-matches','ids':[]},'old pre-registration absence unverified')
 else:
  retired=json.loads(old.read(old.ETC/'unix-admin-h2-canary-retirement-complete.json',0o600));require(retired.get('unit')==pkg.OLD and retired.get('restart_refused') is True and retired.get('listener_closed') is True and retired.get('old_unavailable') is True,'retirement unavailable')
  for name,expected in (('old.retired',b'retired\n'),('old.stopped',b'stopped\n')):
   fd=os.open(pkg.HANDSHAKE/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
   try:
    s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2000,1,0o440),'retirement marker unavailable');old.noacl(fd);require(os.read(fd,128)==expected,'retirement marker changed')
   finally:os.close(fd)
  zero=json.loads(old.read(old.ETC/'unix-admin-h2-canary-snapshot-prezero-complete.json',0o600));require(zero.get('schema')==1 and zero.get('role')=='prezero' and zero.get('epoch_sha256')==base.sha(old.read(old.ETC/'unix-admin-h2-canary-activation-complete.json',0o600)) and zero.get('result')=={'schema':1,'operation':'new-uri-matches','ids':[]},'pre-registration absence unverified')
  post=json.loads(old.read(old.ETC/'unix-admin-h2-canary-after-journal.json',0o600));require(set(post)=={'schema','epoch_sha256','after_probe_sha256','snapshot_sha256','classification'} and type(post['schema']) is int and post['schema']==1 and post['epoch_sha256']==zero['epoch_sha256'] and post['after_probe_sha256']==base.sha(old.read(old.ETC/'unix-admin-h2-canary-after-retirement.json',0o600)) and post['snapshot_sha256']==base.sha(old.read(old.ETC/'unix-admin-h2-canary-snapshot-postretire-complete.json',0o600,maxsize=196608)) and post['classification']=={'forwarded':'retained-nonterminal','old_effect':'absent'},'post-retirement classification unavailable')
 return {'schema':1,'role':role,'unit':unit,'sdk_pid':int(p['MainPID']),'ops_sha256':helpers.ADMIN_SHA,'scope':'one synthetic non-force registration, retain unknown without retry'}
def apply(approved):
 require(plan()==approved,'registration plan changed');role=ROLE;started,complete=records(role);old.store(started,base.canonical(approved)+b'\n',0o600)
 argv=['/usr/bin/systemd-run','--unit='+UNITS[role],'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=After='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=30s','/usr/bin/python3','-I','-B',str(helpers.ADMIN),'register-'+role]
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=40,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'registration unknown')
 result=json.loads(p.stdout);expected='http://127.0.0.1:'+('9081' if role=='old' else '9082');require(set(result)=={'schema','operation','deployment_id','service_name','uri'} and result['schema']==1 and result['operation']=='register-'+role and result['service_name']=='FenceFixture' and result['uri']==expected and isinstance(result['deployment_id'],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',result['deployment_id']),'registration receipt invalid')
 require(old.ctl('show',UNITS[role],'-p','MainPID','--value')=='0' and old.ctl('show',UNITS[role],'-p','Job','--value')=='','registration process unresolved')
 old.store(complete,base.canonical(result)+b'\n',0o600);return result
