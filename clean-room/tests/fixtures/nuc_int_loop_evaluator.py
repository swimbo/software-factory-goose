#!/usr/bin/env python3
"""Disposable, manager-owned host holdouts over isolated read-only candidates."""
import fcntl,hashlib,json,os,pathlib,shlex,stat,subprocess,sys,time,uuid
from docker_batch_guardian import Batch,APPROVED_SLICE,CGROUP_PATH
from nuc_int_loop_task import check_behavior
from trusted_tool_relay import valid_response

IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
EXEC='/tmp/sfactory-gate-linux.X4ZjF1LB/goose-build/execution-target/debug/execution'
FILES=('hello.py','test_hello.py')

def private(path):
 path=pathlib.Path(path)
 st=path.lstat()
 if path.resolve(strict=True)!=path or not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700:raise RuntimeError('private root unavailable')
 return path

def store(path,value):
 with open(path,'x',encoding='utf8') as f:
  os.chmod(path,0o600);json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def freeze(task,source,generation):
 task=private(task);source=pathlib.Path(source)
 private(source.parent)
 if source.resolve(strict=True)!=source or not source.is_dir():raise RuntimeError('candidate path unavailable')
 # This closes admission and requires both recorded roots removed and the exact
 # approved subtree empty before opening a single candidate file.
 Batch(generation,APPROVED_SLICE,CGROUP_PATH).stop()
 root=task/('evaluation-'+uuid.uuid4().hex);root.mkdir(mode=0o700)
 snapshot=root/'snapshot';snapshot.mkdir(mode=0o755);digests={}
 fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  for name in FILES:
   child=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=fd)
   try:
    st=os.fstat(child)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>32768:raise RuntimeError('candidate file rejected')
    with os.fdopen(child,'rb') as f:child=-1;data=f.read(32769)
    if len(data)>32768:raise RuntimeError('candidate file exceeded')
   finally:
    if child>=0:os.close(child)
   with open(snapshot/name,'xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
   (snapshot/name).chmod(0o444);digests[name]=hashlib.sha256(data).hexdigest()
 finally:os.close(fd)
 snapshot.chmod(0o555);store(root/'snapshot.json',digests)
 return root

def recover(root):
 root=private(root)
 for directory in sorted(root.glob('challenge-*')):
  private(directory)
  if any((directory/(role+'.intent')).exists() for role in ('goose','executor')):
   Batch(directory,APPROVED_SLICE,CGROUP_PATH).stop()
 if 'populated 0' not in (CGROUP_PATH/'cgroup.events').read_text():raise RuntimeError('evaluator subtree unresolved')
 if not (root/'recovered.json').exists():store(root/'recovered.json',{'empty':True})

def drive(root):
 root=private(root);snapshot=root/'snapshot';files=json.loads((root/'snapshot.json').read_text())
 policy=root/'policy.toml';policy.write_text('blocked_binaries = ["dd"]\nwrite_commands = ["rm", "mv", "cp", "chmod", "tee"]\nallowed_write_paths = ["/work"]\n');policy.chmod(0o444)
 count=0
 def launch(argv):
  nonlocal count
  if 'populated 0' not in (CGROUP_PATH/'cgroup.events').read_text():raise RuntimeError('slice occupied before challenge')
  directory=root/('challenge-'+str(count));count+=1;directory.mkdir(mode=0o700)
  batch=Batch(directory,APPROVED_SLICE,CGROUP_PATH,snapshot,candidate_readonly=True)
  try:
   batch.prepare_fixed('goose',IMAGE,['-u','-c','import time;time.sleep(20)'],['--entrypoint','python3'])
   options=['--entrypoint','python3','--mount','type=bind,src='+EXEC+',dst=/execution,readonly','--mount','type=bind,src='+str(policy)+',dst=/policy,readonly','--env','SFACTORY_POLICY=/policy','--env','PYTHONDONTWRITEBYTECODE=1','--workdir','/work','--tmpfs','/tmp:rw,nosuid,nodev,size=8m,mode=1777']
   batch.prepare_fixed('executor',IMAGE,['-u','-c','import time;time.sleep(20)'],options);batch.seal();batch.start('executor')
   raw=batch.exec_once(json.dumps({'command':shlex.join(argv)},ensure_ascii=False).encode())
   result=json.loads(raw)
   if not valid_response(result) or result['status']!='executed':raise RuntimeError('challenge unavailable')
   output=subprocess.CompletedProcess(argv,result['exit_code'],result['stdout'].encode(),result['stderr'].encode())
  finally:batch.stop()
  return output
 def run(*args):return launch(['python3','-I','/work/hello.py',*args])
 def tests():return launch(['python3','-I','-m','unittest','discover','-s','/work','-p','test_hello.py'])
 result=check_behavior(run,tests,files)
 # All challenge roots are stopped before the trusted result is published.
 recover(root)
 for name,digest in files.items():
  if hashlib.sha256((snapshot/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('snapshot changed')
 store(root/'result.json',result)

def system(*args,check=True):
 return subprocess.run(['/usr/bin/systemctl','--user',*args],capture_output=True,text=True,check=check,timeout=15)

def launch_manager(task,root):
 task=private(task);root=private(root);script=pathlib.Path(__file__).resolve();unit='sfactory-eval-'+uuid.uuid4().hex+'.service'
 store(root/'unit.json',{'unit':unit,'script':str(script)})
 if system('show',unit,'-p','LoadState','--value',check=False).stdout.strip() not in ('','not-found'):raise RuntimeError('unit collision')
 argv=['/usr/bin/systemd-run','--user','--unit='+unit,'--collect','--property=Description='+unit,'--property=RuntimeMaxSec=180s','--property=TimeoutStopSec=60s','--property=KillMode=control-group','--property=StandardOutput=append:'+str(root/'output.log'),'--property=StandardError=append:'+str(root/'output.log'),'--property=ExecStopPost=/usr/bin/python3 '+str(script)+' recover '+str(root),'/usr/bin/python3',str(script),'drive',str(root)]
 try:
  subprocess.run(argv,capture_output=True,check=True,timeout=15)
  deadline=time.monotonic()+200
  while time.monotonic()<deadline:
   state=system('show',unit,'-p','ActiveState','--value',check=False).stdout.strip()
   if state in ('','inactive','failed'):break
   time.sleep(.2)
  else:raise RuntimeError('evaluation deadline exceeded')
  if not (root/'result.json').exists() or json.loads((root/'recovered.json').read_text())!={'empty':True}:raise RuntimeError('evaluation failed; retain '+str(root))
  recover(root)
  result=json.loads((root/'result.json').read_text())
  # Import only the immutable evaluated blobs into the separately held Git repo.
  for name in FILES:
   with open(task/'repo'/name,'xb') as f:f.write((root/'snapshot'/name).read_bytes())
  store(task/'holdout-result.json',result)
  print(json.dumps({'evaluation':str(root),'result':result}),flush=True)
 finally:
  if system('show',unit,'-p','LoadState','--value',check=False).stdout.strip() not in ('','not-found'):
   if system('show',unit,'-p','Description','--value').stdout.strip()!=unit or str(script) not in system('show',unit,'-p','ExecStart','--value').stdout:raise RuntimeError('unit identity unresolved')
   system('stop',unit)

if __name__=='__main__':
 action=sys.argv[1]
 if action=='recover':recover(pathlib.Path(sys.argv[2]))
 elif action=='drive':drive(pathlib.Path(sys.argv[2]))
 elif action=='evaluate':
  task,source,generation=map(pathlib.Path,sys.argv[2:5]);root=freeze(task,source,generation);launch_manager(task,root)
 else:raise RuntimeError('invalid action')
