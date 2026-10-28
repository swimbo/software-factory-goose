#!/usr/bin/env python3
"""Run only on authorized NUC: isolated labeled Docker/systemd-slice fixture."""
import json
import os
import pathlib
import subprocess
import time

IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
LABEL='org.software-factory.nuc-slice-spike'
token=os.environ['SFACTORY_TOKEN']
if len(token)!=32 or any(c not in '0123456789abcdef' for c in token): raise ValueError('invalid task token')
parent='sfactory'+token+'.slice'
worker_slice='sfactory'+token+'-worker.slice'
slice_path=pathlib.Path('/sys/fs/cgroup')/parent/worker_slice
containers=[]

ESCAPE=r'''import errno,os,sys,time
os.setsid(); assert os.getsid(0)==os.getpid()
assert os.geteuid()==65534
status=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
assert int(status['CapEff'].strip(),16)==0 and status['NoNewPrivs'].strip()=='1'
try:
 open('/sys/fs/cgroup/cgroup.procs','w').write(str(os.getpid()))
except OSError as e:
 assert e.errno in (errno.EROFS,errno.EACCES,errno.EPERM)
 print('CGROUP_WRITE_DENIED '+str(e.errno),flush=True)
else:
 print('CGROUP_WRITE_ALLOWED',flush=True)
os.write(int(sys.argv[1]),b'R')
assert os.read(int(sys.argv[2]),1)==b'G'
print('AFTER_GUARDIAN',flush=True)
time.sleep(3)
print('LATE_MARKER',flush=True)
time.sleep(1)
'''
GUARDIAN=r'''import os,subprocess,sys,time
ready_r,ready_w=os.pipe(); gate=int(sys.argv[1])
p=subprocess.Popen([sys.executable,'-u','-c',%r,str(ready_w),str(gate)],stdout=sys.stderr,pass_fds=(ready_w,gate))
os.close(ready_w); assert os.read(ready_r,1)==b'R'
print('GUARDIAN_READY',flush=True)
time.sleep(12)
''' % ESCAPE
MAIN=r'''import os,subprocess,sys,time
gate_r,gate_w=os.pipe()
p=subprocess.Popen([sys.executable,'-u','-c',%r,str(gate_r)],stdout=subprocess.PIPE,text=True,pass_fds=(gate_r,))
os.close(gate_r); assert p.stdout.readline().strip()=='GUARDIAN_READY'
p.kill(); p.wait(); print('GUARDIAN_REAPED',flush=True)
os.write(gate_w,b'G'); os.close(gate_w)
time.sleep(8)
''' % GUARDIAN

def run(*args, check=True, timeout=10):
 return subprocess.run(['docker',*args],capture_output=True,text=True,check=check,timeout=timeout)
def info(target):
 r=run('inspect',target,check=False)
 if r.returncode:
  if 'no such object' in r.stderr.lower(): return None
  raise RuntimeError('inspection unresolved: '+target+' '+r.stderr)
 o=json.loads(r.stdout)[0]
 if (o['Config']['Labels'] or {}).get(LABEL)!=token: raise RuntimeError('identity label mismatch')
 if len(target)==64 and o['Id']!=target: raise RuntimeError('identity ID mismatch')
 return o

def create(role,slice_name,code):
 name='sfactory-'+token+'-'+role; containers.append(name)
 r=run('create','--name',name,'--label',LABEL+'='+token,'--cgroup-parent',slice_name,
  '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
  '--pids-limit','24','--memory','96m','--cpus','0.5','--user','65534:65534',
  '--entrypoint','python3','--pull','never',IMAGE,'-u','-c',code)
 ident=r.stdout.strip()
 if len(ident)!=64 or not info(ident): raise RuntimeError('invalid created identity')
 obj=info(ident)
 if obj['Mounts'] or obj['HostConfig']['Binds'] or obj['HostConfig']['NetworkMode']!='none': raise RuntimeError('unexpected mounts or network')
 containers[-1]=ident
 run('start',ident)
 return ident

def logs(ident):
 r=run('logs',ident,check=False); return r.stdout+r.stderr

def wait_log(ident, text, timeout=7):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  s=logs(ident)
  if text in s: return s
  time.sleep(.05)
 raise RuntimeError('missing '+text+' output='+logs(ident))

def remove(ident):
 obj=info(ident)
 if obj is None: return
 run('rm','--force',obj['Id'])
 if info(obj['Id']) is not None: raise RuntimeError('container removal unresolved')

try:
 if run('ps','-a','--filter','label='+LABEL+'='+token,'--format','{{.ID}}').stdout.strip(): raise RuntimeError('existing task containers')
 if 'populated 0' not in (slice_path/'cgroup.events').read_text(): raise RuntimeError('existing task slice not empty')
 anchor=create('anchor',parent,'import time;time.sleep(25)')
 positive=create('positive',worker_slice,MAIN)
 text=wait_log(positive,'AFTER_GUARDIAN')
 if 'CGROUP_WRITE_ALLOWED' in text or 'CGROUP_WRITE_DENIED ' not in text: raise RuntimeError('migration denial unverified')
 wait_log(positive,'LATE_MARKER')
 print('POSITIVE: migration write denied; escaped child survived guardian and emitted marker',flush=True)
 remove(positive); containers.remove(positive)
 worker=create('worker',worker_slice,MAIN)
 text=wait_log(worker,'AFTER_GUARDIAN')
 if 'CGROUP_WRITE_ALLOWED' in text or 'CGROUP_WRITE_DENIED ' not in text: raise RuntimeError('migration denial unverified')
 pid=info(worker)['State']['Pid']
 cgroup=pathlib.Path('/proc',str(pid),'cgroup').read_text().strip()
 if worker_slice not in cgroup or worker not in cgroup: raise RuntimeError('worker slice membership mismatch '+cgroup)
 events=slice_path/'cgroup.events'
 slice_inode=slice_path.stat().st_ino
 if 'populated 1' not in events.read_text(): raise RuntimeError('positive populated check failed')
 run('kill',worker)
 observation=''
 end=time.monotonic()+5
 while time.monotonic()<end:
  try: observation=events.read_text()
  except OSError as exc:
   observation='unavailable: '+str(exc); break
  if 'populated 0' in observation: break
  time.sleep(.005)
 time.sleep(3.2)
 marker='LATE_MARKER' in logs(worker)
 if slice_path.stat().st_ino != slice_inode: raise RuntimeError('slice identity changed')
 print('KILL: marker='+str(marker)+' events='+repr(observation),flush=True)
 if marker or 'populated 0' not in observation: raise RuntimeError('independent empty proof unavailable')
finally:
 errors=[]
 for item in reversed(containers):
  try: remove(item)
  except Exception as exc: errors.append(str(exc))
 for unit in (worker_slice,parent):
  r=subprocess.run(['systemctl','show',unit,'-p','ActiveState','--value'],capture_output=True,text=True,timeout=5)
  print('SLICE '+unit+' active='+r.stdout.strip(),flush=True)
 if errors: raise RuntimeError('cleanup unresolved: '+'; '.join(errors))
print('LIMIT: worker could not write visible cgroup, but external cgroup escape and owner/engine death remain unproved')
