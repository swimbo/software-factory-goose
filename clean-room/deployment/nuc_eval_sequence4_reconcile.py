"""Exact-ID cleanup of the synthetic evaluator's unknown fourth result."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGK';TARGET='42N2TT6XVVTZ4BVRH69NFGM50K';ID='48d0f98f995c2bfd75e889aefb2c9d5c0bc3225fc67a2b5836a7f9fe2e264309'
ROOT=old.ETC;STATE=pathlib.Path('/var/lib/software-factory-goose/stop');BASE=pathlib.Path('/var/lib/software-factory-goose/evaluator')/G/'broker';NAME='software-factory-goose-eval-canary';PREV='sfactory-evaluator-canary-coordinator-v2-20261030.service'
INTENT=ROOT/'evaluator-sequence4-reconcile-started.json';DONE=ROOT/'evaluator-sequence4-reconcile-complete.json'
def require(x,msg):
 if not x:raise RuntimeError(msg)
def helper():
 raw=old.read(old.PREFIX/'root-launch-host.py',0o755,'604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e',1000000);h={'__name__':'exact_eval_cleanup'};exec(compile(raw,'<pinned-helper>','exec'),h);return h
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (INTENT,DONE,ROOT/'evaluator-sequence4-remove-intent.json')),'reconciliation occupied');old.directory(BASE,0,0,0o700)
 require(old.ctl('show',PREV,'-p','ActiveState','--value')=='failed' and old.ctl('show',PREV,'-p','MainPID','--value')=='0' and old.ctl('show',PREV,'-p','Job','--value')=='','coordinator not terminal')
 files=set(os.listdir(BASE));expected={f'{n:02}.{s}' for n in (1,2,3) for s in ('intent','deadline-intent','deadline-armed','create-intent','created','start-intent','exit-observed','remove-intent','removed','done')}|{f'04.{s}' for s in ('intent','deadline-intent','deadline-armed','create-intent','created','start-intent','exit-observed')};require(files==expected,'broker history changed')
 provision=json.loads(old.read(ROOT/'evaluator-canary-provision-complete.json',0o600));cat=json.loads(old.read(ROOT/'evaluator-canary-catalog.json',0o600,provision['catalog_sha256'],65536));entry=cat['challenges'][3];require(entry['target']==TARGET and cat['generation']==G,'fixture changed')
 created=json.loads(old.read(BASE/'04.created',0o600));exit=json.loads(old.read(BASE/'04.exit-observed',0o600));require(created=={'target':TARGET,'id':ID} and exit=={'target':TARGET,'id':ID,'exit_code':0},'container receipt mismatch')
 cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+TARGET.lower()+'.slice');st=cg.stat();events=(cg/'cgroup.events').read_text().splitlines();require((st.st_dev,st.st_ino)==(entry['cgroup_dev'],entry['cgroup_ino']) and events.count('frozen 1')==1 and events.count('populated 0')==1,'cgroup unavailable')
 require(old.read(STATE/(TARGET+'.closed'),0o600)==(TARGET+'\n').encode(),'closure unavailable');obs=json.loads(old.read(STATE/(TARGET+'.observation'),0o600));require(obs.get('target_id')==TARGET and obs.get('boot_id')==cat['boot_id'] and (obs.get('cgroup_dev'),obs.get('cgroup_ino'))==(st.st_dev,st.st_ino) and all(obs.get(k) is True for k in ('observed','closed','frozen','empty')) and obs.get('engine_reconciled') is False,'stop unavailable')
 timer='sfactorydeadline'+TARGET.lower()+'.timer';require(old.ctl('show',timer,'-p','ActiveState','--value')=='inactive' and old.ctl('show',timer,'-p','Job','--value')=='','timer unresolved')
 att=json.loads(old.read(ROOT/'evaluator-canary-attestation-complete.json',0o600));unit=old.UNIT/(NAME+'.service');socket=old.UNIT/(NAME+'.socket');install=json.loads(old.read(ROOT/'evaluator-canary-service-started.json',0o600));old.read(unit,0o644,install['service_sha256']);old.read(socket,0o644,install['socket_sha256'])
 for name in (NAME+'.service',NAME+'.socket'):
  for k,v in (('LoadState','loaded'),('ActiveState','active'),('Names',name),('FragmentPath',str(old.UNIT/name)),('DropInPaths',''),('Job','')):require(old.ctl('show',name,'-p',k,'--value')==v,'fixture unit unavailable')
 require(old.ctl('show',NAME+'.service','-p','MainPID','--value')==str(att['pid']),'broker process changed')
 h=helper();h['engine_guard']();data=json.loads(h['fixed_run'](h['DOCKER']+['inspect',ID]));require(len(data)==1 and data[0]['Id']==ID and data[0]['Name']=='/sfactoryeval'+TARGET.lower() and data[0]['State']['Status']=='exited' and data[0]['State']['Pid']==0 and (data[0]['Config'].get('Labels') or {}).get('org.software-factory.evaluation')==TARGET,'container unavailable')
 return {'generation':G,'target':TARGET,'container_id':ID,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'broker_pid':att['pid'],'scope':'fixture-only exact-ID cleanup; result remains unknown'}
def apply(approved):
 require(plan()==approved,'cleanup plan changed');old.store(INTENT,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 old.ctl('stop',NAME+'.socket');old.ctl('stop',NAME+'.service')
 for name in (NAME+'.socket',NAME+'.service'):
  require(old.ctl('show',name,'-p','ActiveState','--value') in ('inactive','failed') and old.ctl('show',name,'-p','Job','--value')=='','broker stop unavailable')
 require(old.ctl('show',NAME+'.service','-p','MainPID','--value')=='0','broker process still active')
 service_cg=pathlib.Path('/sys/fs/cgroup/system.slice')/(NAME+'.service')
 if service_cg.exists():require((service_cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'broker cgroup still populated')
 cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+TARGET.lower()+'.slice');events=(cg/'cgroup.events').read_text().splitlines();st=cg.stat();require((st.st_dev,st.st_ino)==(approved['cgroup_dev'],approved['cgroup_ino']) and events.count('frozen 1')==1 and events.count('populated 0')==1,'cgroup changed')
 h=helper();h['engine_guard']();obj=json.loads(h['fixed_run'](h['DOCKER']+['inspect',ID]));require(len(obj)==1 and obj[0]['Id']==ID and obj[0]['Name']=='/sfactoryeval'+TARGET.lower() and obj[0]['State']['Status']=='exited' and obj[0]['State']['Pid']==0 and (obj[0]['Config'].get('Labels') or {}).get('org.software-factory.evaluation')==TARGET,'container changed')
 old.store(ROOT/'evaluator-sequence4-remove-intent.json',json.dumps({'id':ID,'target':TARGET},sort_keys=True).encode()+b'\n',0o600);h['fixed_run'](h['DOCKER']+['rm',ID],timeout=15)
 p=subprocess.run(h['DOCKER']+['inspect',ID],env=old.ENV,capture_output=True,timeout=10,check=False);require(p.returncode!=0 and len(p.stderr)<=8192 and b'no such object' in p.stderr.lower(),'removal unknown');h['engine_guard']()
 events=(cg/'cgroup.events').read_text().splitlines();st=cg.stat();require((st.st_dev,st.st_ino)==(approved['cgroup_dev'],approved['cgroup_ino']) and events.count('frozen 1')==1 and events.count('populated 0')==1,'post-removal cgroup changed')
 result={'generation':G,'target':TARGET,'container_id':ID,'exact_id_removed':True,'cgroup_frozen_empty':True,'result':'unknown','replayed':False};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
