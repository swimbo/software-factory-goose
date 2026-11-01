"""Read-only native reproduction of post-kill evaluator checks, never retries."""
import hashlib,json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
UNIT='sfactory-eval-canary4-ownerloss-diagnostic.service';ROOT=old.ETC
START=ROOT/'evaluator-canary4-diagnostic-started.json';DONE=ROOT/'evaluator-canary4-diagnostic-complete.json';SCRIPT=ROOT/'evaluator-canary4-diagnostic.py'
G='01M65RMR3F04YB1B016EBBSXGQ';TARGET='58PB23GQAPJ4QAJ5EX85C97EEY';ID='6392048c312ee6af203a9e36bb7d1c1783130dcbe7cc80346d79fc22957e119c'
CODE="""import json,os,pathlib,sys
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/evaluator4')
import nuc_grant_sidecar_install as old
import nuc_registry_eval_backend as backend
stage='identity'
try:
 f=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
 if os.geteuid()!=0 or f.get('NoNewPrivs','').strip()!='1' or any(int(f[k].strip(),16) for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise RuntimeError('identity')
 state=pathlib.Path('/var/lib/software-factory-goose/stop');target='58PB23GQAPJ4QAJ5EX85C97EEY'
 stage='closure';old.read(state/(target+'.closed'),0o600)
 stage='observation';obs=json.loads(old.read(state/(target+'.observation'),0o600))
 if obs.get('target_id')!=target or not all(obs.get(k) is True for k in ('observed','closed','frozen','empty')):raise RuntimeError('observation')
 stage='catalog';cat=json.loads(old.read(old.ETC/'evaluator-canary4-catalog.json',0o600));entry=cat['challenges'][0]
 stage='snapshot';backend.verify_snapshot(entry,old.noacl)
 stage='helper';raw=old.read(old.PREFIX/'root-launch-host.py',0o755,'604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e',1000000);h={'__name__':'diag'};exec(compile(raw,'<pinned-helper>','exec'),h)
 stage='engine';h['engine_guard']()
 stage='container';c=object.__new__(backend.Backend);c.h=h;c.inspect(entry,'6392048c312ee6af203a9e36bb7d1c1783130dcbe7cc80346d79fc22957e119c','sfactoryeval'+target.lower(),'exited',['-I','-B','/work/hello.py'])
 stage='complete'
except Exception as e:
 print(json.dumps({'stage':stage,'errno':e.errno if isinstance(e,OSError) else None},sort_keys=True),flush=True);raise SystemExit(1)
print(json.dumps({'stage':stage,'errno':None},sort_keys=True),flush=True)
"""
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(x) for x in (START,DONE,SCRIPT)),'diagnostic occupied')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied')
 require(old.ctl('show','software-factory-goose-eval-canary4.service','-p','MainPID','--value')=='0','broker live')
 cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+TARGET.lower()+'.slice');st=cg.stat();events=(cg/'cgroup.events').read_text().splitlines();require((st.st_dev,st.st_ino)==(29,7863445) and events.count('populated 0')==1 and events.count('frozen 1')==1,'cgroup unavailable')
 return {'generation':G,'target':TARGET,'container_id':ID,'program_sha256':hashlib.sha256(CODE.encode()).hexdigest(),'scope':'read-only native diagnostics only'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600);old.store(SCRIPT,CODE.encode(),0o600)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=ProtectSystem=strict','--property=ReadWritePaths=/etc/software-factory-goose /var/lib/software-factory-goose/evaluator /var/lib/software-factory-goose/stop /sys/fs/cgroup','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=MemoryMax=256M','--property=TasksMax=32','--property=RuntimeMaxSec=30s','/usr/bin/python3','-I','-B',str(SCRIPT)]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=40,check=False);require(len(p.stdout)<=4096 and len(p.stderr)<=4096,'diagnostic unknown')
 value=json.loads(p.stdout);require(set(value)=={'stage','errno'} and value['stage'] in ('identity','closure','observation','catalog','snapshot','helper','engine','container','complete') and (value['errno'] is None or type(value['errno']) is int),'diagnostic output unavailable')
 require(old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','diagnostic termination unknown')
 old.store(DONE,json.dumps(value,sort_keys=True).encode()+b'\n',0o600);return value
