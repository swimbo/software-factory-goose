"""Exact-ID cleanup of the synthetic evaluator's unknown owner-loss attempt."""
import hashlib,json,os,pathlib,subprocess,sys
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGQ';TARGET='58PB23GQAPJ4QAJ5EX85C97EEY';ID='6392048c312ee6af203a9e36bb7d1c1783130dcbe7cc80346d79fc22957e119c'
ROOT=old.ETC;STATE=pathlib.Path('/var/lib/software-factory-goose/stop');BASE=pathlib.Path('/var/lib/software-factory-goose/evaluator')/G/'broker';NAME='software-factory-goose-eval-canary4';PREV='sfactory-evaluator-canary4-ownerloss-client.service'
INTENT=ROOT/'evaluator-canary4-ownerloss-reconcile-started.json';DONE=ROOT/'evaluator-canary4-ownerloss-reconcile-complete.json'
def require(x,msg):
 if not x:raise RuntimeError(msg)
def helper():
 raw=old.read(old.PREFIX/'root-launch-host.py',0o755,'604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e',1000000);h={'__name__':'exact_eval_cleanup'};exec(compile(raw,'<pinned-helper>','exec'),h);return h
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (INTENT,DONE,ROOT/'evaluator-canary4-ownerloss-reconcile-remove-intent.json')),'reconciliation occupied');old.directory(BASE,0,0,0o700)
 require(old.ctl('show',PREV,'-p','ActiveState','--value')=='failed' and old.ctl('show',PREV,'-p','MainPID','--value')=='0' and old.ctl('show',PREV,'-p','Job','--value')=='','coordinator not terminal')
 files=set(os.listdir(BASE));expected={f'01.{s}' for s in ('intent','deadline-intent','deadline-armed','create-intent','created','start-intent')};require(files==expected,'broker history changed')
 provision=json.loads(old.read(ROOT/'evaluator-canary4-provision-complete.json',0o600));cat=json.loads(old.read(ROOT/'evaluator-canary4-catalog.json',0o600,provision['catalog_sha256'],65536));entry=cat['challenges'][0];require(entry['target']==TARGET and cat['generation']==G and cat.get('purpose')=='synthetic-evaluator-canary4-only','fixture changed')
 created=json.loads(old.read(BASE/'01.created',0o600));require(created=={'target':TARGET,'id':ID},'container receipt mismatch')
 cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+TARGET.lower()+'.slice');st=cg.stat();events=(cg/'cgroup.events').read_text().splitlines();require((st.st_dev,st.st_ino)==(entry['cgroup_dev'],entry['cgroup_ino']) and events.count('frozen 1')==1 and events.count('populated 0')==1,'cgroup unavailable')
 require(old.read(STATE/(TARGET+'.closed'),0o600)==(TARGET+'\n').encode(),'closure unavailable');obs=json.loads(old.read(STATE/(TARGET+'.observation'),0o600));require(obs.get('target_id')==TARGET and obs.get('boot_id')==cat['boot_id'] and (obs.get('cgroup_dev'),obs.get('cgroup_ino'))==(st.st_dev,st.st_ino) and all(obs.get(k) is True for k in ('observed','closed','frozen','empty')) and obs.get('engine_reconciled') is False,'stop unavailable')
 timer='sfactorydeadline'+TARGET.lower()+'.timer';require(old.ctl('show',timer,'-p','ActiveState','--value')=='inactive' and old.ctl('show',timer,'-p','Job','--value')=='','timer unresolved')
 att=json.loads(old.read(ROOT/'evaluator-canary4-attestation-complete.json',0o600));unit=old.UNIT/(NAME+'.service');socket=old.UNIT/(NAME+'.socket');install=json.loads(old.read(ROOT/'evaluator-canary4-service-started.json',0o600));old.read(unit,0o644,install['service_sha256']);old.read(socket,0o644,install['socket_sha256'])
 for name in (NAME+'.service',NAME+'.socket'):
  for k,v in (('LoadState','loaded'),('ActiveState','failed' if name.endswith('.service') else 'inactive'),('Names',name),('FragmentPath',str(old.UNIT/name)),('DropInPaths',''),('Job','')):require(old.ctl('show',name,'-p',k,'--value')==v,'fixture unit unavailable')
 require(old.ctl('show',NAME+'.service','-p','MainPID','--value')=='0' and old.ctl('show',NAME+'.service','-p','Result','--value')=='signal','broker process changed')
 require(old.ctl('show',NAME+'.service','-p','ExecMainCode','--value')=='2' and old.ctl('show',NAME+'.service','-p','ExecMainStatus','--value')=='9' and old.ctl('show',NAME+'.service','-p','InvocationID','--value')=='29a5b9acce9f4c2098cc4203ef7155e8','broker signal identity changed')
 native=json.loads(old.read(ROOT/'evaluator-canary4-native-started.json',0o600));require(native.get('driver_plan',{}).get('broker_pid')==att['pid'] and native.get('driver_plan',{}).get('target')==TARGET,'native intent mismatch');raw=old.read(ROOT/'evaluator-canary4-native-driver.py',0o600);require(hashlib.sha256(raw).hexdigest()==native.get('native_program_sha256')=='76323f48806e7683521deb38e40b891730d66591eb2864d4479a89519ec14dfc','native program changed')
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
 # Recheck the real broker's durable-intent refusal without engine effects.
 sys.path.insert(0,str(old.PREFIX/'evaluator4'))
 import nuc_registry_eval_canary_runtime as runtime
 import nuc_registry_eval_broker as broker
 runtime.verify_sources()
 class Never:
  calls=0
  def launch_and_reconcile(self,*args):
   self.calls+=1
   raise RuntimeError('backend unexpectedly called')
 never=Never();fd=os.open(BASE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  req=json.loads(old.read(BASE/'01.intent',0o600));cat=json.loads(old.read(ROOT/'evaluator-canary4-catalog.json',0o600));core=broker.Broker(fd,cat['snapshot_sha256'],never,G,old.noacl)
  try:core.run(2002,req)
  except broker.Unavailable:pass
  else:raise RuntimeError('replay admitted')
  require(never.calls==0 and not os.path.lexists(BASE/'01.done'),'replay reached backend')
 finally:os.close(fd)
 h=helper();h['engine_guard']();obj=json.loads(h['fixed_run'](h['DOCKER']+['inspect',ID]));require(len(obj)==1 and obj[0]['Id']==ID and obj[0]['Name']=='/sfactoryeval'+TARGET.lower() and obj[0]['State']['Status']=='exited' and obj[0]['State']['Pid']==0 and (obj[0]['Config'].get('Labels') or {}).get('org.software-factory.evaluation')==TARGET,'container changed')
 old.store(ROOT/'evaluator-canary4-ownerloss-reconcile-remove-intent.json',json.dumps({'id':ID,'target':TARGET},sort_keys=True).encode()+b'\n',0o600);h['fixed_run'](h['DOCKER']+['rm',ID],timeout=15)
 p=subprocess.run(h['DOCKER']+['inspect',ID],env=old.ENV,capture_output=True,timeout=10,check=False);require(p.returncode!=0 and len(p.stderr)<=8192 and b'no such object' in p.stderr.lower(),'removal unknown');h['engine_guard']()
 events=(cg/'cgroup.events').read_text().splitlines();st=cg.stat();require((st.st_dev,st.st_ino)==(approved['cgroup_dev'],approved['cgroup_ino']) and events.count('frozen 1')==1 and events.count('populated 0')==1,'post-removal cgroup changed')
 result={'generation':G,'target':TARGET,'container_id':ID,'exact_id_removed':True,'cgroup_frozen_empty':True,'result':'unknown','replayed':False,'replay_denied':True,'broker_sigkill_confirmed':True};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
