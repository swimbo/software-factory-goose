"""Separate fixed, sanitized read-only diagnostic after native verification failure."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_eval_package_install as package
import nuc_registry_eval_package_verify as verify
START=old.ETC/'evaluator-package-diagnostic-started.json';DONE=old.ETC/'evaluator-package-diagnostic-complete.json';UNIT='sfactory-evaluator-package-diagnostic.service'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and os.path.lexists(verify.START) and not os.path.lexists(verify.DONE) and not os.path.lexists(START) and not os.path.lexists(DONE),'diagnostic unavailable')
 require(old.ctl('show',verify.UNIT,'-p','ActiveState','--value')=='failed' and old.ctl('show',verify.UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',verify.UNIT,'-p','Job','--value')=='','prior unit not terminal')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','diagnostic occupied')
 roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for root in map(pathlib.Path,roots):
  for name in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/name),'unit collision')
 return {'schema':1,'unit':UNIT,'prior_exit_status':old.ctl('show',verify.UNIT,'-p','ExecMainStatus','--value'),'scope':'fixed UID2002 sanitized read-only package diagnostic'}
def apply(approved):
 require(plan()==approved,'diagnostic changed');old.store(START,package.canonical(approved),0o600)
 code=verify.CODE.replace('for name,digest in pins.items():',"stage='metadata'\nfor name,digest in pins.items():").replace('for name in pins:',"stage='import'\nfor name in pins:")
 wrapper='import json\nstage="bootstrap"\nname=""\ntry:\n exec('+repr('PINS='+repr(package.PINS)+'\n'+code)+')\nexcept Exception as e:\n print(json.dumps({"schema":1,"stage":stage,"module":name if name in '+repr(list(package.PINS))+' else None,"category":type(e).__name__},sort_keys=True,separators=(",",":")))\n'
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-eval','--property=Group=sfgoose-eval','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=PrivateNetwork=yes','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=25s','/usr/bin/python3','-I','-B','-c',wrapper]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=35,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=8192,'diagnostic unknown')
 result=json.loads(p.stdout);require(isinstance(result,dict) and result.get('schema')==1 and set(result) in ({'schema','stage','module','category'},{'schema','uid','files','imports'}),'diagnostic result unavailable')
 require(old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','diagnostic process unresolved');old.store(DONE,package.canonical(result),0o600);return result
