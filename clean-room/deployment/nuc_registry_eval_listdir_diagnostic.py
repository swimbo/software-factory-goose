"""Fixed native UID2002 directory search diagnostic; no file listing output."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_eval_package_install as package
import nuc_registry_eval_package_diagnostic as prior
START=old.ETC/'evaluator-listdir-diagnostic-started.json';DONE=old.ETC/'evaluator-listdir-diagnostic-complete.json';UNIT='sfactory-evaluator-listdir-diagnostic.service'
CODE="""import errno,json,os
if (os.getuid(),os.geteuid(),os.getgid(),os.getegid())!=(2002,2002,2002,2002):raise RuntimeError('identity')
s=dict(x.split(':',1) for x in open('/proc/self/status').read().splitlines() if ':' in x)
if s.get('NoNewPrivs','').strip()!='1' or any(int(s.get('Cap'+n,'1').strip(),16) for n in ('Inh','Prm','Eff','Bnd','Amb')):raise RuntimeError('privileges')
try:os.listdir('/usr/local/libexec/software-factory-goose/evaluator-production')
except OSError as e:result='EACCES' if e.errno==errno.EACCES else 'OTHER_ERROR'
else:result='ALLOWED'
print(json.dumps({'schema':1,'listdir':result},sort_keys=True,separators=(',',':')))
"""
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'diagnostic occupied')
 require(json.loads(old.read(prior.DONE,0o600))=={'schema':1,'stage':'import','module':'nuc_grant_sidecar_install.py','category':'ModuleNotFoundError'},'prior diagnostic unavailable')
 old.directory(package.DEST,0,2002,0o710);require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied')
 roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for root in map(pathlib.Path,roots):
  for name in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/name),'unit collision')
 return {'schema':1,'unit':UNIT,'scope':'UID2002 fixed directory list permission only; no contents'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,package.canonical(approved),0o600)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-eval','--property=Group=sfgoose-eval','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=PrivateNetwork=yes','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',CODE]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and len(p.stdout)<=1024 and len(p.stderr)<=4096,'diagnostic unknown');result=json.loads(p.stdout)
 require(result.get('schema')==1 and result.get('listdir') in ('EACCES','OTHER_ERROR','ALLOWED') and old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','diagnostic invalid')
 old.store(DONE,package.canonical(result),0o600);return result
