"""Run the fixed synthetic owner-loss driver under a native cap-zero root unit."""
import hashlib,json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_eval_canary4_owner_loss as child
UNIT='sfactory-eval-canary4-ownerloss-native.service'
START=old.ETC/'evaluator-canary4-native-started.json';DONE=old.ETC/'evaluator-canary4-native-complete.json';SCRIPT=old.ETC/'evaluator-canary4-native-driver.py'
# Bridge composition injects exact source bytes; they are pinned in PLAN.
DEPENDENCY_SOURCE='UNAVAILABLE';DRIVER_SOURCE='UNAVAILABLE'
def require(v,m):
 if not v:raise RuntimeError(m)
def program(expected):
 return ("import types,sys,json,os,pathlib\n"+
 "f=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)\n"+
 "if os.geteuid()!=0 or f.get('NoNewPrivs','').strip()!='1' or any(int(f[k].strip(),16) for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise RuntimeError('native privilege mismatch')\n"+
 "m=types.ModuleType('nuc_grant_sidecar_install');sys.modules[m.__name__]=m;exec(compile("+repr(DEPENDENCY_SOURCE)+",'<pinned-support>','exec'),m.__dict__)\n"+
 "m=types.ModuleType('fixed_ownerloss');exec(compile("+repr(DRIVER_SOURCE)+",'<pinned-driver>','exec'),m.__dict__)\n"+
 "print(json.dumps(m.apply(json.loads("+repr(json.dumps(expected,sort_keys=True))+")),sort_keys=True),flush=True)\n").encode()
def plan():
 require(os.geteuid()==0 and DEPENDENCY_SOURCE!='UNAVAILABLE' and DRIVER_SOURCE!='UNAVAILABLE' and not any(os.path.lexists(p) for p in (START,DONE,SCRIPT)),'native scope occupied')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied')
 for parent in ('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system'):
  for name in [UNIT,UNIT+'.d','service.d']+[UNIT[:i+1]+'service.d' for i,c in enumerate(UNIT[:-8]) if c=='-']:
   require(not os.path.lexists(pathlib.Path(parent)/name),'unit alias occupied')
 spec=child.plan()
 return {'driver_plan':spec,'native_program_sha256':hashlib.sha256(program(spec)).hexdigest(),'unit':UNIT,'scope':'synthetic cap-zero native owner-loss only'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600);old.store(SCRIPT,program(approved['driver_plan']),0o600)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=ProtectSystem=strict','--property=ReadWritePaths=/etc/software-factory-goose /var/lib/software-factory-goose/evaluator /var/lib/software-factory-goose/stop /sys/fs/cgroup','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=MemoryMax=256M','--property=TasksMax=32','--property=RuntimeMaxSec=120s','/usr/bin/python3','-I','-B',str(SCRIPT)]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=130,check=False)
 require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'native outcome unknown')
 result=json.loads(p.stdout);require(result.get('generation')==approved['driver_plan']['generation'] and result.get('target')==approved['driver_plan']['target'] and result.get('result')=='unknown' and all(result.get(k) is True for k in ('broker_killed_by_pidfd','attached_start_inflight','worker_processes_confined','distinct_sessions_observed','deadline_frozen_empty','exact_id_removed','replay_denied')),'native result unavailable')
 require(old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','native termination unavailable')
 old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
