"""One fixed read-only namespace listener check for pre-effect continuation."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as activation
START=old.ETC/'unix-admin-h2-canary-no-listener-started.json';DONE=old.ETC/'unix-admin-h2-canary-no-listener-complete.json';UNIT='sfactory-unix-admin-h2-canary-no-listener.service'
CODE="""import json,os,socket
if (os.getuid(),os.geteuid(),os.getgid(),os.getegid())!=(2000,2000,2000,2000):raise RuntimeError('identity')
d=dict(x.split(':',1) for x in open('/proc/self/status').read().splitlines() if ':' in x)
if d.get('NoNewPrivs','').strip()!='1' or any(int(d.get('Cap'+n,'1').strip(),16) for n in ('Inh','Prm','Eff','Bnd','Amb')):raise RuntimeError('privileges')
ns=os.stat('/proc/self/ns/net')
for port in (9081,9082):
 s=socket.socket();s.settimeout(2)
 try:s.connect(('127.0.0.1',port))
 except ConnectionRefusedError:pass
 else:raise RuntimeError('listener alive')
 finally:s.close()
for p in ('/proc/self/net/tcp','/proc/self/net/tcp6'):
 for line in open(p).read().splitlines()[1:]:
  f=line.split()
  if f[1].rsplit(':',1)[1].upper() in ('2379','237A') and f[3]=='0A':raise RuntimeError('listener alive')
print(json.dumps({'schema':1,'closed':True,'net_dev':ns.st_dev,'net_ino':ns.st_ino},sort_keys=True,separators=(',',':')))
"""
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'listener check already attempted')
 epoch=json.loads(old.read(activation.DONE,0o600));require(epoch.get('boot_id')==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'boot changed')
 for n in (base.NET,base.SERVER):require(activation.identity(n)==epoch['identities'][n],'epoch changed')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied')
 roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for root in map(pathlib.Path,roots):
  for name in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/name),'unit collision')
 return {'schema':1,'epoch_sha256':base.sha(old.read(activation.DONE,0o600)),'unit':UNIT,'scope':'read-only fixed namespace listener check'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=8','--property=RuntimeMaxSec=15s','/usr/bin/python3','-I','-B','-c',CODE]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=25,check=False);require(p.returncode==0 and len(p.stdout)<=1024 and len(p.stderr)<=4096,'listener status unknown');observed=json.loads(p.stdout);require(set(observed)=={'schema','closed','net_dev','net_ino'} and observed['schema']==1 and observed['closed'] is True and type(observed['net_dev']) is int and observed['net_dev']>0 and type(observed['net_ino']) is int and observed['net_ino']>0,'listener observation invalid');require(old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','probe unresolved')
 result={'schema':1,'epoch_sha256':approved['epoch_sha256'],'listeners_closed':True,'net_dev':observed['net_dev'],'net_ino':observed['net_ino']};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
