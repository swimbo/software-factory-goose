"""Read-only inventory of the exact synthetic owner-loss attempt."""
import json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGQ';TARGET='58PB23GQAPJ4QAJ5EX85C97EEY';BASE=pathlib.Path('/var/lib/software-factory-goose/evaluator')/G;STATE=pathlib.Path('/var/lib/software-factory-goose/stop');CG=pathlib.Path('/sys/fs/cgroup')/('sfactory'+TARGET.lower()+'.slice')
def plan():
 if os.geteuid()!=0:raise RuntimeError('root required')
 intent=json.loads(old.read(old.ETC/'evaluator-canary4-ownerloss-started.json',0o600))
 if intent.get('generation')!=G or intent.get('target')!=TARGET:raise RuntimeError('intent unavailable')
 old.directory(BASE/'broker',0,0,0o700);names=sorted(os.listdir(BASE/'broker'))
 if len(names)>64 or any(re.fullmatch(r'[0-9]{2}\.[a-z-]+',n) is None for n in names):raise RuntimeError('records unavailable')
 st=CG.stat();events=(CG/'cgroup.events').read_text().splitlines()
 if (st.st_dev,st.st_ino)!=(intent['cgroup_dev'],intent['cgroup_ino']):raise RuntimeError('cgroup changed')
 result={}
 for unit in ('software-factory-goose-eval-canary4.service','software-factory-goose-eval-canary4.socket','sfactory-evaluator-canary4-ownerloss-client.service','sfactorydeadline'+TARGET.lower()+'.timer','sfactorydeadline'+TARGET.lower()+'.service'):
  result[unit]={k:old.ctl('show',unit,'-p',k,'--value') for k in ('LoadState','ActiveState','MainPID','Job','Result')}
 ids={}
 for suffix in ('.closed','.observation','.eval-deadline-armed.json'):
  path=STATE/(TARGET+suffix)
  ids[suffix]=os.path.lexists(path)
 if '01.created' in names:
  created=json.loads(old.read(BASE/'broker'/'01.created',0o600));ident=created.get('id')
  if created.get('target')!=TARGET or not isinstance(ident,str) or re.fullmatch('[0-9a-f]{64}',ident) is None:raise RuntimeError('identity unavailable')
  raw=old.read(old.PREFIX/'root-launch-host.py',0o755,'604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e',1000000);h={'__name__':'canary_inventory'};exec(compile(raw,'<pinned-helper>','exec'),h);h['engine_guard']()
  p=subprocess.run(h['DOCKER']+['inspect',ident],env=h['ENV'],capture_output=True,timeout=10,check=False)
  if p.returncode==0:
   obj=json.loads(p.stdout);o=obj[0] if len(obj)==1 else {};ids['container']={'id':ident,'name':o.get('Name'),'status':o.get('State',{}).get('Status'),'pid':o.get('State',{}).get('Pid')}
  elif len(p.stderr)<=8192 and b'no such object' in p.stderr.lower():ids['container']={'id':ident,'absent':True}
  else:raise RuntimeError('container inventory unknown')
  h['engine_guard']()
 return {'generation':G,'target':TARGET,'records':names,'events':events,'stop_files':ids,'units':result,'read_only':True}
def apply(reviewed):raise RuntimeError('read-only inventory')
