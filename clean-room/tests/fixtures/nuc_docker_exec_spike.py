#!/usr/bin/env python3
"""Disposable two-root batch recovery test on the authorized NUC."""
import pathlib, subprocess, sys
MODE='exec'
HERE=pathlib.Path(__file__).resolve().parent
batch=(HERE/'docker_batch_guardian.py').read_text(); guardian=(HERE/'docker_owner_guardian.py').read_text()
image='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
module='IMAGE='+repr(image)+'\nLABEL='+repr('org.software-factory.escape-spike')+'\nMAIN="unused"\n'
DRIVER=r'''import json,os,pathlib,shutil,subprocess,sys,tempfile,time,uuid
MODE=__MODE__
PARENT='sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice'; SLICE='sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0-worker.slice'; CG=pathlib.Path('/sys/fs/cgroup')/PARENT/SLICE
LABEL='org.software-factory.batch-anchor'; IMAGE=__IMAGE__
def docker(*args,check=True): return subprocess.run(['docker',*args],capture_output=True,text=True,timeout=10,check=check)
def inspect(target,token):
 r=docker('inspect',target,check=False)
 if r.returncode:
  if 'no such object' in r.stderr.lower(): return None
  raise RuntimeError('inspection unresolved')
 o=json.loads(r.stdout)[0]
 if (o['Config']['Labels'] or {}).get(LABEL)!=token: raise RuntimeError('anchor mismatch')
 if len(target)==64 and o['Id']!=target: raise RuntimeError('anchor ID mismatch')
 return o
def waitfile(p,sec=12):
 end=time.monotonic()+sec
 while time.monotonic()<end:
  if p.exists(): return
  time.sleep(.02)
 raise RuntimeError('missing '+str(p))
if 'populated 0' not in (CG/'cgroup.events').read_text(): raise RuntimeError('slice not empty')
tok=uuid.uuid4().hex; name='sfactory-batch-anchor-'+tok; anchor=None; maker=None; unit='sfactory-'+uuid.uuid4().hex+'.service'; attempted=False
temp=tempfile.mkdtemp(prefix='sfactory-batch-')
if True:
 root=pathlib.Path(temp); (root/'docker_batch_guardian.py').write_text(__BATCH__); (root/'docker_owner_guardian.py').write_text(__GUARDIAN__); (root/'docker_owned_escape_spike.py').write_text(__MODULE__)
 data=root/'data'; data.mkdir(mode=0o700); candidate=root/'candidate'; candidate.mkdir(mode=0o777); candidate.chmod(0o777)
 policy=root/'policy.toml'; policy.write_text('blocked_binaries = ["dd"]\nwrite_commands = ["rm", "mv", "cp", "chmod", "tee"]\nallowed_write_paths = ["/work"]\n'); policy.chmod(0o444)
 sys.path.insert(0,temp); from docker_batch_guardian import Batch
 b=Batch(data,SLICE,CG,candidate)
 code="""import json,pathlib,sys,time
from docker_batch_guardian import Batch
root=pathlib.Path(sys.argv[1]); b=Batch(root,sys.argv[2],sys.argv[3],sys.argv[5]); image=sys.argv[4]; policy=sys.argv[6]
b.prepare_fixed('goose',image,['-u','-c','import time;time.sleep(12)'],['--entrypoint','python3'])
options=['--entrypoint','python3','--mount','type=bind,src=/tmp/sfactory-gate-linux.X4ZjF1LB/goose-build/execution-target/debug/execution,dst=/execution,readonly','--mount','type=bind,src='+policy+',dst=/policy,readonly','--env','SFACTORY_POLICY=/policy','--workdir','/work']
b.prepare_fixed('executor',image,['-u','-c','import time;time.sleep(12)'],options)
b.seal(); b.start('executor')
out=b.exec_once(b'{\"command\":\"printf EXEC_OK | tee /work/result\"}')
(root/'result.json').write_bytes(out); (root/'ready').write_text('ready'); time.sleep(15)
"""
 try:
  a=docker('create','--name',name,'--label',LABEL+'='+tok,'--cgroup-parent',PARENT,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','24','--memory','96m','--cpus','0.5','--user','65534:65534','--entrypoint','python3','--pull','never',IMAGE,'-u','-c','import time;time.sleep(30)')
  anchor=a.stdout.strip()
  if len(anchor)!=64 or not inspect(anchor,tok): raise RuntimeError('anchor identity unresolved')
  docker('start',anchor)
  (root/'maker.py').write_text(code)
  if MODE=='manager':
   recovery=root/'recovery.py'
   recovery.write_text("import pathlib,sys\nfrom docker_batch_guardian import Batch\nb=Batch(sys.argv[1],sys.argv[2],sys.argv[3]); b.stop(); (pathlib.Path(sys.argv[1])/'recovered').write_text('ok')\n")
   prior=subprocess.run(['systemctl','--user','show',unit,'-p','LoadState','--value'],capture_output=True,text=True,timeout=8)
   if prior.stdout.strip() not in ('','not-found'): raise RuntimeError('unit name collision')
   attempted=True
   subprocess.run(['systemd-run','--user','--unit='+unit,'--collect','--property=Description='+unit,
    '--property=RuntimeMaxSec=20s','--property=TimeoutStopSec=15s',
    '--property=ExecStopPost=/usr/bin/python3 '+str(recovery)+' '+str(data)+' '+SLICE+' '+str(CG),
    '/usr/bin/python3',str(root/'maker.py'),str(data),SLICE,str(CG),IMAGE],capture_output=True,text=True,timeout=10,check=True)
  else:
   maker=subprocess.Popen([sys.executable,str(root/'maker.py'),str(data),SLICE,str(CG),IMAGE,str(candidate),str(policy)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  waitfile(data/'ready')
  if 'populated 1' not in (CG/'cgroup.events').read_text(): raise RuntimeError('positive cgroup observation missing')
  if (candidate/'result').read_text()!='EXEC_OK' or 'EXEC_OK' not in (data/'result.json').read_text(): raise RuntimeError('bounded executor output or candidate write missing')
  ids=[]
  for role in ('goose','executor'):
   m=b.read(role+'.manifest'); ids.append(m['id'])
  if len(set(ids))!=2: raise RuntimeError('root IDs collide')
  if MODE=='manager':
   desc=subprocess.run(['systemctl','--user','show',unit,'-p','Description','--value'],capture_output=True,text=True,timeout=8,check=True).stdout.strip()
   executable=subprocess.run(['systemctl','--user','show',unit,'-p','ExecStart','--value'],capture_output=True,text=True,timeout=8,check=True).stdout
   if desc!=unit or str(root/'maker.py') not in executable: raise RuntimeError('unit identity mismatch')
   subprocess.run(['systemctl','--user','kill','--kill-whom=main','--signal=SIGKILL',unit],capture_output=True,text=True,timeout=8,check=True)
   waitfile(data/'recovered',15)
  else:
   maker.kill(); maker.wait(timeout=5)
  recovered=Batch(data,SLICE,CG)
  if not recovered.stop() or not recovered.stop(): raise RuntimeError('batch recovery failed')
  if 'populated 0' not in (CG/'cgroup.events').read_text(): raise RuntimeError('empty subtree unverified')
  try: recovered.start('goose')
  except RuntimeError: pass
  else: raise RuntimeError('closed batch readmitted')
  print('PASS: fixed executor accepted bounded stdin, wrote owned candidate; owner killed; batch recovered and slice populated 0',flush=True)
 finally:
  if maker is not None:
   if maker.poll() is None: maker.kill()
   maker.wait(timeout=5)
  if attempted:
   load=subprocess.run(['systemctl','--user','show',unit,'-p','LoadState','--value'],capture_output=True,text=True,timeout=8).stdout.strip()
   if load not in ('','not-found'):
    desc=subprocess.run(['systemctl','--user','show',unit,'-p','Description','--value'],capture_output=True,text=True,timeout=8,check=True).stdout.strip()
    executable=subprocess.run(['systemctl','--user','show',unit,'-p','ExecStart','--value'],capture_output=True,text=True,timeout=8,check=True).stdout
    if desc!=unit or str(root/'maker.py') not in executable: raise RuntimeError('unit identity unresolved')
    subprocess.run(['systemctl','--user','stop',unit],capture_output=True,text=True,timeout=20,check=True)
  # Retain records when either ownership or cleanup is ambiguous; anchor cleanup
  # is attempted independently and remains limited to its random identity.
  errors=[]
  try:
   if any((data/(role+'.intent')).exists() for role in ('goose','executor')): b.stop()
  except Exception as exc: errors.append('batch: '+str(exc))
  try:
   if inspect(anchor or name,tok) is not None: docker('rm','--force',anchor or name)
  except Exception as exc: errors.append('anchor: '+str(exc))
  if errors:
   print('RETAINED '+temp+' '+'; '.join(errors),file=sys.stderr,flush=True)
   raise RuntimeError('owned cleanup unresolved')
  shutil.rmtree(temp)
print('LIMIT: synthetic command only; no actual Goose/relay, hostile candidate race, authenticated brake or manager-loss proof')
'''
script=DRIVER.replace('__MODE__',repr(MODE)).replace('__BATCH__',repr(batch)).replace('__GUARDIAN__',repr(guardian)).replace('__MODULE__',repr(module)).replace('__IMAGE__',repr(image))
if __name__=='__main__':
 r=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=script,text=True,timeout=50)
 sys.exit(r.returncode)
