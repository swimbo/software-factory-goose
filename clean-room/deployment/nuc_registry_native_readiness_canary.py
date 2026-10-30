"""Single native preclaim readiness unit; no grant or workload starts."""
import hashlib,json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGG'
UNIT='sfactory-registry-readiness-'+G.lower()+'.service'
START=old.ETC/'registry-readiness-started.json';DONE=old.ETC/'registry-readiness-complete.json'
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','SYSTEMD_IN_CHROOT':'0'}
# Supplied by the bridge from locally reviewed, source-hashed files.
OLD_SOURCE='';READINESS_SOURCE=''

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def program():
 return "import types,sys\nm=types.ModuleType('nuc_grant_sidecar_install');sys.modules['nuc_grant_sidecar_install']=m;exec(compile("+repr(OLD_SOURCE)+",'<fixed-support>','exec'),m.__dict__)\nexec(compile("+repr(READINESS_SOURCE)+",'<fixed-readiness>','exec'))\nprint(json.dumps(plan(),sort_keys=True,separators=(',',':')))\n"
def plan():
 require(os.geteuid()==0 and OLD_SOURCE and READINESS_SOURCE,'missing fixed source or root')
 require(not os.path.lexists(START) and not os.path.lexists(DONE),'readiness already attempted')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','readiness unit occupied')
 code=program();require(len(code)<100000,'readiness source too large')
 return {'generation':G,'unit':UNIT,'program_sha256':hashlib.sha256(code.encode()).hexdigest(),'scope':'native read-only root preclaim checks; no grant or engine creation'}
def apply(approved):
 require(plan()==approved,'plan changed')
 old.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=256M','--property=TasksMax=32','--property=RuntimeMaxSec=120s','/usr/bin/python3','-I','-B','-c',program()]
 p=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=140,check=False)
 require(p.returncode==0 and len(p.stdout)<=16384 and len(p.stderr)<=8192,'native readiness outcome unknown')
 result=json.loads(p.stdout);require(result['generation']==G and result['attestor_passed'] is True and result['claim_requested'] is False and result['container_started'] is False and result['provider_called'] is False,'unexpected readiness result')
 old.store(DONE,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 return result
