"""Read-only sanitized inventory of fixture challenge 04; no mutation."""
import json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGK';ROOT=old.ETC;BASE=pathlib.Path('/var/lib/software-factory-goose/evaluator')/G/'broker';STOP=pathlib.Path('/var/lib/software-factory-goose/stop')
def require(x,msg):
 if not x:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0,'root required');old.directory(BASE,0,0,0o700)
 receipt=json.loads(old.read(ROOT/'evaluator-canary-provision-complete.json',0o600));cat=json.loads(old.read(ROOT/'evaluator-canary-catalog.json',0o600,receipt['catalog_sha256'],65536));e=cat['challenges'][3];target=e['target']
 records={}
 for name in ('04.intent','04.deadline-intent','04.deadline-armed','04.create-intent','04.created','04.start-intent','04.exit-observed','04.remove-intent','04.removed','04.done'):
  path=BASE/name
  if not os.path.lexists(path):records[name]='absent';continue
  data=old.read(path,0o600,maxsize=16384);records[name]='present'
 created=json.loads(old.read(BASE/'04.created',0o600));observed=json.loads(old.read(BASE/'04.exit-observed',0o600));ident=created.get('id');require(created.get('target')==target and observed.get('target')==target and observed.get('id')==ident and isinstance(ident,str) and re.fullmatch('[0-9a-f]{64}',ident),'identity unavailable')
 raw=old.read(old.PREFIX/'root-launch-host.py',0o755,'604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e',1000000);h={'__name__':'fixture_inventory'};exec(compile(raw,'<pinned-helper>','exec'),h);h['engine_guard']();objects=json.loads(h['fixed_run'](h['DOCKER']+['inspect',ident]));require(len(objects)==1 and objects[0]['Id']==ident,'object unavailable');o=objects[0];state=o['State'];host=o['HostConfig']
 import sys
 sys.path.insert(0,str(old.PREFIX/'evaluator'));import nuc_registry_eval_backend as backend
 request=json.loads(old.read(BASE/'04.intent',0o600));args=request['args'];cmd=['-I','-B','/work/hello.py',*args];name='sfactoryeval'+target.lower();checker=backend.Backend.__new__(backend.Backend);checker.h=h
 checks={}
 for label,fn in [('validator',lambda:checker.inspect(e,ident,name,'exited',cmd)),('snapshot',lambda:backend.verify_snapshot(e,old.noacl))]:
  try:fn();checks[label]='pass'
  except Exception:checks[label]='denied'
 config=o['Config'];checks['command_matches']=config.get('Cmd')==cmd;checks['mounts_count']=len(o.get('Mounts',[]));checks['image_matches']=o.get('Image')==backend.IMAGE
 cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+target.lower()+'.slice');st=cg.stat();events=(cg/'cgroup.events').read_text().splitlines();require((st.st_dev,st.st_ino)==(e['cgroup_dev'],e['cgroup_ino']),'cgroup changed')
 times={name:(BASE/name).stat().st_mtime_ns for name in ('04.intent','04.deadline-armed','04.created','04.start-intent','04.exit-observed')};times['stop_observation']=(STOP/(target+'.observation')).stat().st_mtime_ns;origin=times['04.intent'];elapsed_ms={k:(v-origin)//1000000 for k,v in times.items()}
 observation=json.loads(old.read(STOP/(target+'.observation'),0o600));closed=old.read(STOP/(target+'.closed'),0o600)
 checks['stop_exact']=observation.get('target_id')==target and observation.get('boot_id')==cat['boot_id'] and (observation.get('cgroup_dev'),observation.get('cgroup_ino'))==(st.st_dev,st.st_ino) and all(observation.get(k) is True for k in ('observed','closed','frozen','empty')) and observation.get('engine_reconciled') is False
 try:
  checks['helper_closure_matches']=h['rootfile'](STOP/(target+'.closed'))==(target+'\n').encode();checks['helper_observation_matches']=json.loads(h['rootfile'](STOP/(target+'.observation')))==observation
 except Exception:checks['helper_observation_matches']=False
 return {'elapsed_ms':elapsed_ms,'checks':checks,'generation':G,'sequence':4,'target':target,'container_id':ident,'records':records,'recorded_exit_code':observed.get('exit_code'),'docker_status':state.get('Status'),'docker_exit_code':state.get('ExitCode'),'docker_started':state.get('StartedAt') not in (None,'','0001-01-01T00:00:00Z'),'log_config':host.get('LogConfig'),'cgroup_frozen':events.count('frozen 1')==1,'cgroup_empty':events.count('populated 0')==1,'closed_record_matches':closed==(target+'\n').encode(),'stop_observation':{k:observation.get(k) for k in ('observed','closed','frozen','empty','engine_reconciled')},'provider_called':False,'read_only':True}
def apply(approved):raise RuntimeError('read-only inventory')
