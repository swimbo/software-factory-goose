"""One-shot synthetic owner-loss control. Unknown effects remain quarantined."""
import json, os, pathlib, re, signal, subprocess, sys, time
import nuc_grant_sidecar_install as old

G='01M65RMR3F04YB1B016EBBSXGP'
ROOT=old.ETC
BASE=pathlib.Path('/var/lib/software-factory-goose/evaluator')/G
BROKER='software-factory-goose-eval-canary3.service'
SOCKET='software-factory-goose-eval-canary3.socket'
CLIENT='sfactory-evaluator-canary3-ownerloss-client.service'
START=ROOT/'evaluator-canary3-ownerloss-started.json'
DONE=ROOT/'evaluator-canary3-ownerloss-complete.json'
CODE="""import os,pathlib,runpy
if (os.getuid(),os.geteuid(),os.getgid(),os.getegid())!=(2002,2002,2002,2002):raise RuntimeError('identity unavailable')
f=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
if f.get('NoNewPrivs','').strip()!='1' or any(int(f[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise RuntimeError('privileges unavailable')
runpy.run_path('/usr/local/libexec/software-factory-goose/evaluator3/nuc_registry_eval_canary_coordinator.py',run_name='__main__')
"""
def require(value,message):
 if not value:raise RuntimeError(message)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'scope occupied')
 require(old.ctl('show',CLIENT,'-p','LoadState','--value')=='not-found','client occupied')
 for parent in ('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system'):
  candidates=[CLIENT,CLIENT+'.d','service.d']+[CLIENT[:i+1]+'service.d' for i,c in enumerate(CLIENT[:-8]) if c=='-']
  for name in candidates:
   require(not os.path.lexists(pathlib.Path(parent)/name),'client alias occupied')
 provision=json.loads(old.read(ROOT/'evaluator-canary3-provision-complete.json',0o600))
 raw=old.read(ROOT/'evaluator-canary3-catalog.json',0o600,provision['catalog_sha256'],65536);cat=json.loads(raw)
 att=json.loads(old.read(ROOT/'evaluator-canary3-attestation-complete.json',0o600));active=json.loads(old.read(ROOT/'evaluator-canary3-activation-complete.json',0o600))
 require(cat.get('generation')==G and cat.get('purpose')=='synthetic-evaluator-canary3-only' and len(cat.get('challenges',[]))==22 and att.get('generation')==G and active.get('generation')==G and active.get('pid')==att.get('pid') and not os.listdir(BASE/'broker'),'fixture unavailable')
 require(old.ctl('show',BROKER,'-p','MainPID','--value')==str(att['pid']) and old.ctl('show',BROKER,'-p','ActiveState','--value')=='active','broker unavailable')
 entry=cat['challenges'][0];target=entry['target'];cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+target.lower()+'.slice');st=cg.stat();events=(cg/'cgroup.events').read_text().splitlines()
 require((st.st_dev,st.st_ino)==(entry['cgroup_dev'],entry['cgroup_ino']) and events.count('populated 0')==1 and events.count('frozen 0')==1,'target unavailable')
 return {'schema':1,'generation':G,'target':target,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'broker_pid':att['pid'],'catalog_sha256':provision['catalog_sha256'],'attestation_sha256':att['manifest_sha256'],'scope':'synthetic owner loss only; no provider'}
def wait_for(fn,seconds):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  result=fn()
  if result:return result
  time.sleep(.05)
 raise RuntimeError('observation unknown')
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 # Detached client is never retried. Intent is already durable before manager effects.
 args=['/usr/bin/systemd-run','--quiet','--unit='+CLIENT,'--property=User=sfgoose-eval','--property=Group=sfgoose-eval','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=PrivateNetwork=yes','--property=RestrictAddressFamilies=AF_UNIX','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=60s','--property=LimitCORE=0','/usr/bin/python3','-I','-B','-c',CODE]
 subprocess.run(args,env=old.ENV,timeout=15,check=True,capture_output=True)
 journal=BASE/'broker';target=approved['target'];cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+target.lower()+'.slice')
 def started():
  if not all((journal/name).is_file() for name in ('01.intent','01.deadline-armed','01.created','01.start-intent')):return None
  record=json.loads(old.read(journal/'01.created',0o600));ident=record.get('id')
  if record.get('target')!=target or not isinstance(ident,str) or re.fullmatch('[0-9a-f]{64}',ident) is None:raise RuntimeError('identity unavailable')
  if (cg/'cgroup.events').read_text().splitlines().count('populated 1')!=1:return None
  return ident
 ident=wait_for(started,20)
 # Independently observe the actual task processes, including the setsid child.
 def process_proof():
  pids=[]
  for procs in cg.rglob('cgroup.procs'):
   pids.extend(int(x) for x in procs.read_text().split())
  if len(set(pids))<2:return None
  sessions=set()
  for pid in set(pids):
   status=pathlib.Path('/proc')/str(pid)/'status'
   try:
    fields=dict(line.split(':',1) for line in status.read_text().splitlines() if ':' in line)
    if fields.get('Uid','').split()!=['2001']*4 or fields.get('Gid','').split()!=['2001']*4 or fields.get('NoNewPrivs','').strip()!='1' or fields.get('Seccomp','').strip()!='2' or '2002' in fields.get('Groups','').split() or any(int(fields[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise RuntimeError('candidate privileges mismatch')
    text=(status.parent/'stat').read_text(); tail=text[text.rfind(')')+2:].split();sessions.add(int(tail[3]))
   except FileNotFoundError:return None
  return len(sessions)>=2
 wait_for(process_proof,10)
 # Reuse the exact installed backend's image, label, mount and security validation.
 sys.path.insert(0,str(old.PREFIX/'evaluator3'))
 import nuc_registry_eval_backend as backend
 import nuc_registry_eval_broker as broker
 helper=old.read(old.PREFIX/'root-launch-host.py',0o755,'604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e',1000000);h={'__name__':'owner_loss_helper'};exec(compile(helper,'<pinned-helper>','exec'),h);h['engine_guard']()
 catalog=json.loads(old.read(ROOT/'evaluator-canary3-catalog.json',0o600,approved['catalog_sha256'],65536));entry=catalog['challenges'][0]
 checker=object.__new__(backend.Backend);checker.h=h;name='sfactoryeval'+target.lower();cmd=['-I','-B','/work/hello.py']
 checker.inspect(entry,ident,name,'running',cmd)
 require(old.ctl('show','sfactorydeadline'+target.lower()+'.timer','-p','ActiveState','--value')=='active','deadline unavailable')
 pidfd=os.pidfd_open(approved['broker_pid'],0)
 try:
  require(old.ctl('show',BROKER,'-p','MainPID','--value')==str(approved['broker_pid']) and old.ctl('show',BROKER,'-p','ActiveState','--value')=='active','broker identity changed')
  children=(pathlib.Path('/proc')/str(approved['broker_pid'])/'task'/str(approved['broker_pid'])/'children').read_text().split()
  expected=[str(x) for x in h['DOCKER']]+['start','-a',ident]
  matches=[]
  for child in children:
   try:
    cmdline=(pathlib.Path('/proc')/child/'cmdline').read_bytes().split(b'\0')
    if cmdline and cmdline[-1]==b'':cmdline.pop()
    if cmdline==[x.encode() for x in expected]:matches.append(int(child))
   except FileNotFoundError:continue
  require(len(matches)==1,'attached start is not in flight')
  signal.pidfd_send_signal(pidfd,signal.SIGKILL)
 finally:os.close(pidfd)
 wait_for(lambda:old.ctl('show',BROKER,'-p','MainPID','--value')=='0',10)
 # Once the broker is dead, close its fixture socket to prevent reactivation.
 old.ctl('stop',SOCKET)
 def stopped():
  ev=(cg/'cgroup.events').read_text().splitlines();st=cg.stat()
  return (st.st_dev,st.st_ino)==(approved['cgroup_dev'],approved['cgroup_ino']) and ev.count('frozen 1')==1 and ev.count('populated 0')==1
 wait_for(stopped,55)
 require(not os.path.lexists(journal/'01.done'),'unexpected result')
 state=pathlib.Path('/var/lib/software-factory-goose/stop')
 require(old.read(state/(target+'.closed'),0o600)==(target+'\n').encode(),'closure unavailable')
 observation=json.loads(old.read(state/(target+'.observation'),0o600))
 require(observation.get('target_id')==target and (observation.get('cgroup_dev'),observation.get('cgroup_ino'))==(approved['cgroup_dev'],approved['cgroup_ino']) and observation.get('boot_id')==catalog['boot_id'] and all(observation.get(k) is True for k in ('observed','closed','frozen','empty')) and observation.get('engine_reconciled') is False,'stop observation unavailable')
 def terminal():
  try:h['engine_guard']();checker.inspect(entry,ident,name,'exited',cmd);return True
  except Exception:return False
 wait_for(terminal,15)
 old.store(journal/'01.ownerloss-remove-intent',json.dumps({'target':target,'id':ident},sort_keys=True).encode(),0o600)
 h['fixed_run'](h['DOCKER']+['rm',ident],timeout=15)
 p=subprocess.run(h['DOCKER']+['inspect',ident],env=h['ENV'],capture_output=True,timeout=10,check=False)
 require(p.returncode!=0 and len(p.stderr)<=8192 and b'no such object' in p.stderr.lower() and stopped(),'removal unknown');h['engine_guard']()
 # Replay the durable request directly against the real core. A backend call is a failure.
 class Never:
  calls=0
  def launch_and_reconcile(self,*args):
   self.calls+=1
   raise RuntimeError('replay reached backend')
 never=Never()
 fd=os.open(journal,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  request=json.loads(old.read(journal/'01.intent',0o600));core=broker.Broker(fd,catalog['snapshot_sha256'],never,G,old.noacl)
  try:core.run(2002,request)
  except broker.Unavailable:pass
  else:raise RuntimeError('replay admitted')
  require(never.calls==0,'replay reached backend')
 finally:os.close(fd)
 require(not os.path.lexists(journal/'01.done') and stopped() and old.ctl('show',BROKER,'-p','MainPID','--value')=='0' and old.ctl('show',BROKER,'-p','Job','--value')=='' and old.ctl('show',SOCKET,'-p','ActiveState','--value')=='inactive','unknown outcome changed')
 result={'generation':G,'target':target,'container_id':ident,'broker_killed_by_pidfd':True,'attached_start_inflight':True,'worker_processes_confined':True,'distinct_sessions_observed':True,'deadline_frozen_empty':True,'exact_id_removed':True,'replay_denied':True,'result':'unknown','provider_called':False}
 old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
