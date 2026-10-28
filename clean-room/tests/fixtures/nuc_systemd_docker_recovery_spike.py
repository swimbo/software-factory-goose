#!/usr/bin/env python3
"""Manager-driven owner-loss fixture using the existing NUC Docker slices."""
import pathlib
import subprocess
import sys
MODE=sys.argv[1] if len(sys.argv)==2 else 'normal'
if MODE not in ('normal','precommit'): raise SystemExit('mode must be normal or precommit')
HERE=pathlib.Path(__file__).resolve().parent
source=(HERE/'nuc_docker_slice_spike.py').read_text(); ns={}
exec(source[source.index('ESCAPE='):source.index('\ndef run(')],ns)
guardian=(HERE/'docker_owner_guardian.py').read_text()
image='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
module='IMAGE='+repr(image)+'\nLABEL='+repr('org.software-factory.escape-spike')+'\nMAIN='+repr(ns['MAIN'])+'\n'
SERVICE=r'''import json,os,pathlib,sys,time
from docker_owner_guardian import DisposableContainer,LABEL
root=pathlib.Path(sys.argv[1]); token=sys.argv[2]; owner=DisposableContainer(token)
slice_path=pathlib.Path('/sys/fs/cgroup')/'sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice'/os.environ['SFACTORY_CGROUP_PARENT']
def commit(name,value):
 tmp=root/(name+'.tmp'); fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:
  json.dump(value,f); f.flush(); os.fsync(f.fileno())
 os.replace(tmp,root/(name+'.json'))
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)
intent={'token':token,'label':LABEL,'slice':os.environ['SFACTORY_CGROUP_PARENT'],'inode':slice_path.stat().st_ino}
commit('intent',intent)
ident=owner.prepare()
if os.environ.get('SFACTORY_STAGE')=='precommit':
 (root/'created').write_text('created')
 time.sleep(25)
manifest=dict(intent,id=ident)
commit('manifest',manifest)
(root/'prepared').write_text('prepared')
end=time.monotonic()+8
while not (root/'launch').exists() and time.monotonic()<end: time.sleep(.01)
if not (root/'launch').exists(): raise RuntimeError('launch gate timed out')
owner.launch_prepared()
(root/'ready').write_text('ready')
time.sleep(25)
'''
CLEANUP=r'''import json,os,pathlib,stat,sys,time
from docker_owner_guardian import DisposableContainer,LABEL,docker
root=pathlib.Path(sys.argv[1]); expected=sys.argv[2]; output=root/'cleanup-result'
try:
 def read_checked(name):
  fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW)
  with os.fdopen(fd,'r') as f:
   st=os.fstat(f.fileno())
   if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600 or not stat.S_ISREG(st.st_mode): raise RuntimeError('manifest permissions invalid')
   return json.load(f)
 intent=read_checked('intent.json')
 if intent['token']!=expected or intent['label']!=LABEL or intent['slice']!=os.environ['SFACTORY_CGROUP_PARENT']: raise RuntimeError('intent identity invalid')
 path=pathlib.Path('/sys/fs/cgroup')/'sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice'/intent['slice']
 if path.stat().st_ino!=intent['inode']: raise RuntimeError('slice identity changed')
 owner=DisposableContainer(expected)
 try: m=read_checked('manifest.json')
 except FileNotFoundError:
  # Deterministic name and unique label identify a never-started create only.
  obj=owner.inspect(owner.name)
  if obj is None: raise RuntimeError('missing prepared container; reconciliation unresolved')
  if obj['Name']!='/'+owner.name or obj['HostConfig']['CgroupParent']!=intent['slice'] or obj['State']['Running'] or obj['State']['Status']!='created': raise RuntimeError('prepared identity or state unresolved')
  ident=obj['Id']
  if len(ident)!=64 or any(c not in '0123456789abcdef' for c in ident): raise RuntimeError('prepared ID invalid')
  matches=docker('ps','-a','--filter','label='+LABEL+'='+expected,'--no-trunc','--format','{{.ID}}').stdout.split()
  if matches!=[ident]: raise RuntimeError('prepared label is ambiguous')
  owner.ident=ident; owner.closed=True
  # Never signal a container whose full-ID manifest was not committed. Docker's
  # non-force removal refuses a currently running container.
  docker('rm',ident)
  if owner.inspect(ident) is not None: raise RuntimeError('prepared removal unresolved')
  owner.removed=True; mode='PRECOMMIT'
 else:
  if any(m.get(k)!=intent[k] for k in ('token','label','slice','inode')) or len(m['id'])!=64 or any(c not in '0123456789abcdef' for c in m['id']): raise RuntimeError('manifest identity invalid')
  owner.ident=m['id']; obj=owner.inspect(owner.ident)
  if obj is None or obj['HostConfig']['CgroupParent']!=intent['slice']: raise RuntimeError('worker identity unavailable')
  mode='COMMITTED'
  owner.cleanup(); owner.cleanup()
 deadline=time.monotonic()+5
 while time.monotonic()<deadline:
  if 'populated 0' in (path/'cgroup.events').read_text(): break
  time.sleep(.01)
 else: raise RuntimeError('worker slice not empty')
 if path.stat().st_ino!=intent['inode']: raise RuntimeError('slice identity changed')
 output.write_text('OK '+mode+' '+str(intent['inode']))
except Exception as e:
 output.write_text('ERROR '+str(e)); raise
'''
DRIVER=r'''import json,os,pathlib,queue,subprocess,sys,tempfile,time,uuid
MODE=__MODE__
PARENT='sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice'; SLICE='sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0-worker.slice'; CG=pathlib.Path('/sys/fs/cgroup')/PARENT/SLICE
ANCHOR_LABEL='org.software-factory.nuc-systemd-anchor'
GUARDIAN=__GUARDIAN__; MODULE=__MODULE__; SERVICE=__SERVICE__; CLEANUP=__CLEANUP__
def docker(*args,check=True): return subprocess.run(['docker',*args],capture_output=True,text=True,timeout=10,check=check)
def system(*args,check=True): return subprocess.run(['systemctl','--user',*args],capture_output=True,text=True,timeout=15,check=check)
def anchor_info(target,token):
 r=docker('inspect',target,check=False)
 if r.returncode:
  if 'no such object' in r.stderr.lower(): return None
  raise RuntimeError('anchor inspection unresolved')
 obj=json.loads(r.stdout)[0]
 if (obj['Config']['Labels'] or {}).get(ANCHOR_LABEL)!=token: raise RuntimeError('anchor label mismatch')
 if len(target)==64 and obj['Id']!=target: raise RuntimeError('anchor ID mismatch')
 return obj
def waitfile(path,seconds=10):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if path.exists(): return
  time.sleep(.02)
 raise RuntimeError('missing '+str(path))
if 'populated 0' not in (CG/'cgroup.events').read_text(): raise RuntimeError('slice not empty')
token=uuid.uuid4().hex; unit='sfactory-'+token+'.service'; anchor_token=uuid.uuid4().hex; anchor_name='sfactory-anchor-'+anchor_token; anchor=None; attempted=False
with tempfile.TemporaryDirectory(prefix='sfactory-stoppost-') as temp:
 root=pathlib.Path(temp)
 for name,code in [('docker_owner_guardian.py',GUARDIAN),('docker_owned_escape_spike.py',MODULE),('service.py',SERVICE),('cleanup.py',CLEANUP)]: (root/name).write_text(code)
 sys.path.insert(0,str(root)); from docker_owner_guardian import DisposableContainer
 fallback=DisposableContainer(token)
 try:
  a=docker('create','--name',anchor_name,'--label',ANCHOR_LABEL+'='+anchor_token,'--cgroup-parent',PARENT,
   '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','24','--memory','96m','--cpus','0.5','--user','65534:65534',
   '--entrypoint','python3','--pull','never',__IMAGE__,'-u','-c','import time;time.sleep(30)')
  anchor=a.stdout.strip()
  if len(anchor)!=64 or not anchor_info(anchor,anchor_token): raise RuntimeError('anchor identity unresolved')
  docker('start',anchor)
  prior=system('show',unit,'-p','LoadState','--value',check=False)
  if prior.stdout.strip() not in ('','not-found'): raise RuntimeError('unit name collision')
  attempted=True
  command=['systemd-run','--user','--unit='+unit,'--collect','--property=Description='+unit,
   '--property=RuntimeMaxSec=20s','--property=TimeoutStopSec=12s',
   '--property=ExecStopPost=/usr/bin/python3 '+str(root/'cleanup.py')+' '+str(root)+' '+token,
   '--setenv=SFACTORY_CGROUP_PARENT='+SLICE,'--setenv=SFACTORY_STAGE='+MODE,'/usr/bin/python3',str(root/'service.py'),str(root),token]
  subprocess.run(command,capture_output=True,text=True,check=True,timeout=10)
  if MODE=='precommit':
   waitfile(root/'created'); m=json.loads((root/'intent.json').read_text())
   obj=fallback.inspect(fallback.name)
   if obj is None or obj['State']['Status']!='created' or obj['State']['Running'] or (root/'manifest.json').exists(): raise RuntimeError('precommit crash gate failed')
   fallback.ident=obj['Id']; m['id']=obj['Id']
  else:
   waitfile(root/'prepared'); m=json.loads((root/'manifest.json').read_text()); fallback.ident=m['id']
   obj=fallback.inspect(m['id'])
   if obj is None or obj['State']['Running'] or obj['HostConfig']['CgroupParent']!=SLICE: raise RuntimeError('manifest-before-start control failed')
   (root/'launch').write_text('go'); waitfile(root/'ready')
   deadline=time.monotonic()+8
   while time.monotonic()<deadline:
    logs=docker('logs',m['id'],check=False); out=logs.stdout+logs.stderr
    if 'AFTER_GUARDIAN' in out and 'CGROUP_WRITE_DENIED ' in out: break
    time.sleep(.05)
   else: raise RuntimeError('worker handshake missing')
   if 'populated 1' not in (CG/'cgroup.events').read_text(): raise RuntimeError('worker cgroup not populated')
  if m['token']!=token or m['inode']!=CG.stat().st_ino: raise RuntimeError('committed identity mismatch')
  desc=system('show',unit,'-p','Description','--value').stdout.strip()
  executable=system('show',unit,'-p','ExecStart','--value').stdout
  if desc!=unit or str(root/'service.py') not in executable: raise RuntimeError('unit identity mismatch')
  system('kill','--kill-whom=main','--signal=SIGKILL',unit)
  waitfile(root/'cleanup-result',12)
  result=(root/'cleanup-result').read_text()
  if result!='OK '+('PRECOMMIT' if MODE=='precommit' else 'COMMITTED')+' '+str(m['inode']): raise RuntimeError('cleanup failed: '+result)
  if fallback.inspect(m['id']) is not None: raise RuntimeError('owned worker remains')
  if CG.stat().st_ino!=m['inode'] or 'populated 0' not in (CG/'cgroup.events').read_text(): raise RuntimeError('outside empty check failed')
  print('PASS: '+MODE+' guardian SIGKILL; systemd ExecStopPost cleaned exact container; slice inode='+str(m['inode'])+' populated 0',flush=True)
 finally:
  if attempted:
   load=system('show',unit,'-p','LoadState','--value',check=False).stdout.strip()
   if load not in ('','not-found'):
    desc=system('show',unit,'-p','Description','--value').stdout.strip(); executable=system('show',unit,'-p','ExecStart','--value').stdout
    if desc!=unit or str(root/'service.py') not in executable: raise RuntimeError('fixture unit identity unresolved')
    system('stop',unit,check=False)
  if fallback.inspect(fallback.ident or fallback.name) is not None: fallback.cleanup()
  if anchor_info(anchor or anchor_name,anchor_token) is not None: docker('rm','--force',anchor or anchor_name)
print('LIMIT: systemd/engine loss, worker escape, persistent recovery and independent authentication unproved')
'''
script=DRIVER.replace('__MODE__',repr(MODE)).replace('__GUARDIAN__',repr(guardian)).replace('__MODULE__',repr(module)).replace('__SERVICE__',repr(SERVICE)).replace('__CLEANUP__',repr(CLEANUP)).replace('__IMAGE__',repr(image))
if __name__ == '__main__':
 r=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=script,text=True,timeout=60)
 sys.exit(r.returncode)
