"""Fixed UID2002 read-only evaluator package import and identity proof."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_eval_package_v2_install as package
START=old.ETC/'evaluator-package-v2-verify-started.json';DONE=old.ETC/'evaluator-package-v2-verify-complete.json';UNIT='sfactory-evaluator-package-v2-verify.service'
CODE=r'''import errno,hashlib,importlib,json,os,stat,sys
if (os.getuid(),os.geteuid(),os.getgid(),os.getegid())!=(2002,2002,2002,2002):raise RuntimeError('identity')
s=open('/proc/self/status').read().splitlines();d=dict(x.split(':',1) for x in s if ':' in x)
if d.get('NoNewPrivs','').strip()!='1' or any(int(d.get('Cap'+n,'1').strip(),16)!=0 for n in ('Inh','Prm','Eff','Bnd','Amb')):raise RuntimeError('privileges')
p='/usr/local/libexec/software-factory-goose/evaluator-production-v2';pins=PINS
sys.path.insert(0,p)
for name,digest in pins.items():
 fd=os.open(p+'/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))!=(0,2002,1,0o440):raise RuntimeError('metadata')
  try:os.getxattr(fd,'system.posix_acl_access')
  except OSError as e:
   if e.errno!=errno.ENODATA:raise RuntimeError('ACL unavailable')
  else:raise RuntimeError('ACL present')
  h=hashlib.sha256()
  while b:=os.read(fd,65536):h.update(b)
  if h.hexdigest()!=digest:raise RuntimeError('digest')
 finally:os.close(fd)
for name in pins:
 module=importlib.import_module(name[:-3])
 if os.path.realpath(module.__file__)!=p+'/'+name:raise RuntimeError('import path')
print(json.dumps({'schema':1,'uid':2002,'files':len(pins),'imports':True},sort_keys=True,separators=(',',':')))
'''
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE),'verification occupied')
 require(json.loads(old.read(package.DONE,0o600))=={'schema':1,'installed':True,'activated':False,'evaluated':False},'install unavailable')
 raw=old.read(package.MANIFEST,0o600);require(json.loads(raw)=={'schema':1,'files':package.PINS},'manifest changed');old.directory(package.DEST,0,2002,0o750)
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied')
 roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for root in map(pathlib.Path,roots):
  for name in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/name),'unit collision')
 return {'schema':1,'manifest_sha256':__import__('hashlib').sha256(raw).hexdigest(),'unit':UNIT,'scope':'read-only UID2002 cap-empty package imports; no evaluation'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,package.canonical(approved),0o600)
 code='PINS='+repr(package.PINS)+'\n'+CODE
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-eval','--property=Group=sfgoose-eval','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=PrivateNetwork=yes','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=25s','/usr/bin/python3','-I','-B','-c',code]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=35,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=8192,'native verification unknown')
 result=json.loads(p.stdout);require(result=={'schema':1,'uid':2002,'files':len(package.PINS),'imports':True} and old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','native result unknown')
 old.store(DONE,package.canonical(result),0o600);return result
