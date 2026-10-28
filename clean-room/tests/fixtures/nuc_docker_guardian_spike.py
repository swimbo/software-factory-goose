#!/usr/bin/env python3
"""Run the reusable owned-container guardian on the authorized NUC over SSH."""
import pathlib
import subprocess
import sys

HERE=pathlib.Path(__file__).resolve().parent
source=(HERE/'nuc_docker_slice_spike.py').read_text()
namespace={}
exec(source[source.index('ESCAPE='):source.index('\ndef run(')], namespace)
guardian=(HERE/'docker_owner_guardian.py').read_text()
module='IMAGE='+repr('sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937')+'\nLABEL='+repr('org.software-factory.escape-spike')+'\nMAIN='+repr(namespace['MAIN'])+'\n'
DRIVER=r'''import os,pathlib,queue,subprocess,sys,tempfile,threading,time,uuid
TOKEN='6a2ae9a8ef374a84b94c15a1b1d4d7f0'
PARENT='sfactory'+TOKEN+'.slice'; SLICE='sfactory'+TOKEN+'-worker.slice'
SLICE_PATH=pathlib.Path('/sys/fs/cgroup')/PARENT/SLICE
ANCHOR_LABEL='org.software-factory.nuc-owner-anchor'
GUARDIAN_SRC=__GUARDIAN__
MODULE_SRC=__MODULE__
def run(*args, check=True):
 return subprocess.run(['docker',*args],capture_output=True,text=True,timeout=10,check=check)
def anchor_info(target,token):
 import json
 r=run('inspect',target,check=False)
 if r.returncode:
  if 'no such object' in r.stderr.lower(): return None
  raise RuntimeError('anchor inspection unresolved')
 obj=json.loads(r.stdout)[0]
 if (obj['Config']['Labels'] or {}).get(ANCHOR_LABEL)!=token: raise RuntimeError('anchor label mismatch')
 if len(target)==64 and obj['Id']!=target: raise RuntimeError('anchor ID mismatch')
 return obj
if 'populated 0' not in (SLICE_PATH/'cgroup.events').read_text(): raise RuntimeError('worker slice not empty')
if run('ps','-a','--filter','label='+ANCHOR_LABEL,'--format','{{.ID}}').stdout.strip(): raise RuntimeError('unexpected fixture anchor exists')
inode=SLICE_PATH.stat().st_ino
anchor_token=uuid.uuid4().hex; name='sfactory-anchor-'+anchor_token; anchor=None
worker_token=uuid.uuid4().hex; controller=None; guardian=None; worker=None
with tempfile.TemporaryDirectory(prefix='sfactory-ownerloss-') as root:
 pathlib.Path(root,'docker_owner_guardian.py').write_text(GUARDIAN_SRC)
 pathlib.Path(root,'docker_owned_escape_spike.py').write_text(MODULE_SRC)
 sys.path.insert(0,root)
 from docker_owner_guardian import DisposableContainer
 fallback=DisposableContainer(worker_token)
 try:
  a=run('create','--name',name,'--label',ANCHOR_LABEL+'='+anchor_token,'--cgroup-parent',PARENT,
   '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
   '--pids-limit','24','--memory','96m','--cpus','0.5','--user','65534:65534',
   '--entrypoint','python3','--pull','never',__IMAGE__,'-u','-c','import time;time.sleep(25)')
  anchor=a.stdout.strip()
  if len(anchor)!=64 or not anchor_info(anchor,anchor_token): raise RuntimeError('anchor ID unresolved')
  run('start',anchor)
  controller=subprocess.Popen(['/bin/sleep','30'],stdout=subprocess.PIPE)
  env=os.environ.copy(); env['SFACTORY_CGROUP_PARENT']=SLICE
  guardian=subprocess.Popen([sys.executable,str(pathlib.Path(root,'docker_owner_guardian.py')),worker_token],
    stdin=controller.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
  controller.stdout.close()
  lines=queue.Queue()
  def reader():
   for line in guardian.stdout: lines.put(line.strip())
  threading.Thread(target=reader,daemon=True).start()
  first=lines.get(timeout=15)
  if not first.startswith('READY '): raise RuntimeError('guardian not ready: '+first)
  worker=first.split()[1]; fallback.ident=worker
  obj=fallback.inspect(worker)
  if obj is None or obj['HostConfig']['CgroupParent']!=SLICE or obj['Mounts'] or obj['HostConfig']['Binds'] or obj['HostConfig']['NetworkMode']!='none': raise RuntimeError('worker config mismatch')
  pid=obj['State']['Pid']; membership=pathlib.Path('/proc',str(pid),'cgroup').read_text()
  if SLICE not in membership or worker not in membership: raise RuntimeError('worker membership mismatch')
  deadline=time.monotonic()+8
  while time.monotonic()<deadline:
   logs=run('logs',worker,check=False); out=logs.stdout+logs.stderr
   if 'AFTER_GUARDIAN' in out and 'CGROUP_WRITE_DENIED ' in out: break
   time.sleep(.05)
  else: raise RuntimeError('escaped-session handshake missing')
  if 'populated 1' not in (SLICE_PATH/'cgroup.events').read_text(): raise RuntimeError('positive populated check failed')
  if guardian.poll() is not None or controller.poll() is not None: raise RuntimeError('controller or guardian died early')
  controller.kill(); controller.wait(timeout=5)
  if lines.get(timeout=15)!='REMOVED EOF': raise RuntimeError('guardian did not confirm cleanup')
  if guardian.wait(timeout=5)!=0: raise RuntimeError('guardian failed')
  if fallback.inspect(worker) is not None: raise RuntimeError('worker container still present')
  event=(SLICE_PATH/'cgroup.events').read_text()
  if SLICE_PATH.stat().st_ino!=inode or 'populated 0' not in event: raise RuntimeError('same slice emptiness not observed')
  print('PASS: controller SIGKILL; guardian removed owned worker; same slice inode='+str(inode)+' '+repr(event),flush=True)
 finally:
  if controller is not None:
   if controller.poll() is None: controller.kill()
   controller.wait(timeout=5)
  if guardian is not None:
   try: guardian.wait(timeout=15)
   except subprocess.TimeoutExpired:
    guardian.kill(); guardian.wait(timeout=5)
  candidate=worker or fallback.name
  if fallback.inspect(candidate) is not None: fallback.cleanup()
  if anchor_info(anchor or name,anchor_token) is not None: run('rm','--force',anchor or name)
  if guardian is not None:
   guardian.stdout.close(); guardian.stderr.close()
print('LIMIT: host guardian/daemon loss, full migration denial, authenticated brake and cross-identity isolation unproved')
'''
script=DRIVER.replace('__GUARDIAN__',repr(guardian)).replace('__MODULE__',repr(module)).replace('__IMAGE__',repr('sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'))
result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=script,text=True,timeout=60)
sys.exit(result.returncode)
