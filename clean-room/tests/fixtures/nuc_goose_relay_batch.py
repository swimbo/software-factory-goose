#!/usr/bin/env python3
"""Synthetic Goose -> peer-gated host -> isolated execution and disposable journal."""
import contextlib,json,os,pathlib,shutil,tempfile,threading,time,subprocess
from docker_batch_guardian import Batch
from docker_owner_guardian import docker
from nuc_goose_relay_service import SyntheticService,sse,ARGS
from nuc_live_goose_service import LiveService
from nuc_run_fence import RunFence
from nuc_task_request_pin import TaskRequestPin
from nuc_file_contract import canonical_arguments
from nuc_stream_contract import RAW_SSE_BYTES
from nuc_bifrost_stream import parse as parse_stream
from nuc_structured_file_relay import WRITE_TOOL
from nuc_original_create_guard import check as check_original_fence
from nuc_goose_relay_socket import Listener
ROOT=pathlib.Path(os.environ.get('SFACTORY_FIXTURE_CODE_ROOT','/tmp/sfactory-tool-relay-code.f6O9xEoS'))
GOOSE='/tmp/sfactory-gate-linux.X4ZjF1LB/goose-build/goose-linux-fixture'
EXEC='/tmp/sfactory-gate-linux.X4ZjF1LB/goose-build/execution-target/debug/execution'
IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
SLICE='sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0-worker.slice'
CGROUP='/sys/fs/cgroup/sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice/'+SLICE

def main():
 journal=os.environ['SFACTORY_FIXTURE_JOURNAL'];assert os.getuid()==1000
 writer=os.environ.get('SFACTORY_WRITER_PREFLIGHT')=='1'
 negative=os.environ.get('SFACTORY_WRITER_NEGATIVE','')
 large=os.environ.get('SFACTORY_LARGE_SSE_PREFLIGHT')=='1'
 recorded=os.environ.get('SFACTORY_RECORDED_SSE_DIAGNOSTIC')=='1'
 if negative not in ('','wrong_tool','duplicate_keys') or (negative and not writer):raise RuntimeError('invalid fixture mode')
 configured=os.environ.get('SFACTORY_BATCH_ROOT')
 if writer and not configured:raise RuntimeError('writer requires retained batch root')
 if writer:check_original_fence()
 scope=contextlib.nullcontext(configured) if configured else tempfile.TemporaryDirectory(prefix='batch-',dir=ROOT)
 with scope as tmp:
  root=pathlib.Path(tmp)
  if configured and (root.is_symlink() or not root.is_dir() or root.stat().st_uid!=os.getuid() or (root.stat().st_mode & 0o777)!=0o700):raise RuntimeError('invalid batch root')
  root.chmod(0o700);fixtures=root/'fixtures';fixtures.mkdir(mode=0o755);manifest=root/'manifest';manifest.mkdir(mode=0o700)
  for name in ('nuc_goose_relay_worker.py','nuc_stream_contract.py'):
   shutil.copyfile(ROOT/name,fixtures/name);(fixtures/name).chmod(0o444)
  gate=root/'gate';gate.mkdir(mode=0o711)
  policy=root/'policy.toml';policy.write_text('blocked_binaries = ["dd"]\nwrite_commands = ["rm", "mv", "cp", "chmod", "tee"]\nallowed_write_paths = ["/work"]\n');policy.chmod(0o444)
  candidate=os.environ.get('SFACTORY_WRITER_CANDIDATE') if writer else None
  if writer and (not candidate or not os.path.isabs(candidate)):raise RuntimeError('candidate unavailable')
  batch=Batch(manifest,SLICE,CGROUP,candidate=candidate);listener=None;thread=None
  try:
   worker_options=['--mount','type=bind,src='+GOOSE+',dst=/goose,readonly','--mount','type=bind,src='+str(fixtures)+',dst=/fixtures,readonly','--mount','type=bind,src='+str(gate)+',dst=/gate,readonly','--tmpfs','/work:rw,exec,nosuid,nodev,size=128m,mode=1777','--entrypoint','python3']
   if writer:worker_options.extend(['--env','SFACTORY_TOOL_MODE=write_files'])
   if recorded:worker_options.extend(['--env','SFACTORY_DIAGNOSTICS=1'])
   if 'SFACTORY_TASK_PROMPT' in os.environ:worker_options.extend(['--env','SFACTORY_TASK_PROMPT='+os.environ['SFACTORY_TASK_PROMPT']])
   if os.environ.get('SFACTORY_FIXTURE_HOLD')=='1':worker_options.extend(['--env','SFACTORY_FIXTURE_HOLD=1'])
   executor_options=['--mount','type=bind,src='+EXEC+',dst=/execution,readonly','--mount','type=bind,src='+str(policy)+',dst=/policy,readonly','--tmpfs','/work:rw,nosuid,nodev,size=16m,mode=1777','--workdir','/work','--env','SFACTORY_POLICY=/policy','--entrypoint','python3']
   fixed="import subprocess,sys; r=subprocess.run(['/execution','--tool-request'],input=b'{\"command\":\"printf RELAY_OK\"}',stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);sys.stdout.buffer.write(r.stdout);sys.exit(r.returncode)"
   batch.prepare_fixed('goose',IMAGE,['-B','/fixtures/nuc_goose_relay_worker.py'],worker_options)
   if writer:
    executor_options=['--mount','type=bind,src='+str(ROOT/'nuc_factory_write_files.py')+',dst=/factory-writer.py,readonly','--mount','type=bind,src='+str(ROOT/'nuc_file_contract.py')+',dst=/nuc_file_contract.py,readonly','--entrypoint','python3']
    batch.prepare_fixed('executor',IMAGE,['-B','-c','import time; time.sleep(300)'],executor_options,executor_kind='writer')
   else:batch.prepare_fixed('executor',IMAGE,['-B','-c',fixed],executor_options)
   batch.seal()
   if writer:batch.start('executor')
   def execute(_arguments):
    if recorded:
     print('OFFLINE_DIAGNOSTIC mock_writer_only',flush=True)
     return {'status':'executed','exit_code':0,'stdout':'Both task files written.','stderr':''}
    if writer:return json.loads(batch.write_once(canonical_arguments(_arguments)))
    ident=batch.start('executor');status=docker('wait',ident).stdout.strip()
    if status!='0':raise RuntimeError('execution failed')
    output=docker('logs',ident).stdout
    if len(output.encode())>65536:raise RuntimeError('output exceeded')
    return json.loads(output)
   if os.environ.get('SFACTORY_FENCE_PREFLIGHT')=='1' or writer:
    snapshot_path=os.environ.get('SFACTORY_WRITER_SNAPSHOT') if writer else '/tmp/sfactory-real-int-loop-20261028/goose-initial-v2.json'
    if not snapshot_path:raise RuntimeError('snapshot unavailable')
    snapshot=json.loads(pathlib.Path(snapshot_path).read_text())
    prompt=os.environ['SFACTORY_TASK_PROMPT'];pin=TaskRequestPin(snapshot,prompt)
    fence_root=root/'fence';fence_root.mkdir(mode=0o700);fence=RunFence(fence_root,'synthetic-run','synthetic-task',create=True)
    recorded_models={'ollama-cloud/deepseek-v4-pro:0813','ollama-cloud/deepseek-v4.1-flash:1017','deepseek-v4-pro:0813','deepseek-v4.1-flash:1017'}
    recorded_body=pathlib.Path('/tmp/sfactory-real-int-loop-20261028/attempt9/provider-body-0.bin').read_bytes() if recorded else None
    recorded_model=parse_stream(recorded_body,recorded_models,'factory__write_files')['model'] if recorded else None
    class SyntheticTransport:
     def __init__(self):self.turn=0
     def send(self,body):
      if body.get('model')!='auto':raise RuntimeError('route unavailable')
      self.turn+=1
      if self.turn==1:
       if recorded:return recorded_body
       arguments={'files':{'hello.py':'print(1)\n','test_hello.py':'pass\n'}} if writer else ARGS
       argtext='{}' if negative=='duplicate_keys' else json.dumps(arguments,separators=(',',':'))
       if negative=='duplicate_keys':argtext='{"files":{},"files":{}}'
       result=sse({'role':'assistant','tool_calls':[{'index':0,'id':'factory-probe','type':'function','function':{'name':'factory__shell' if negative=='wrong_tool' or not writer else 'factory__write_files','arguments':argtext}}]},'tool_calls')
       if large:
        if not writer or negative or len(result)>=RAW_SSE_BYTES:raise RuntimeError('invalid large fixture')
        offset=result.index(b'\n\n');result=result[:offset]+b' '*(RAW_SSE_BYTES-len(result))+result[offset:]
       return result
      if self.turn==2:
       final=sse({'role':'assistant','content':'OFFLINE_FACTORY_DONE'},'stop')
       return final.replace(b'gpt-4o-mini',recorded_model.encode()) if recorded else final
      raise RuntimeError('repeat denied')
    transport=SyntheticTransport()
    def capture_continuation(body):
     path=root/'continuation-private.json'
     if path.exists():return
     data=json.dumps(body,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
     if len(data)>65536:raise RuntimeError('diagnostic request too large')
     fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
     with os.fdopen(fd,'wb') as output:output.write(data);output.flush();os.fsync(output.fileno())
     fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
    service=LiveService(initial=snapshot,initial_validator=pin,allowed_models=recorded_models if recorded else {'gpt-4o-mini'},fence=fence,transport=transport,execute=execute,tool_mode='write_files' if writer else 'shell',diagnostics=recorded,continuation_capture=capture_continuation if recorded else None)
   else:service=SyntheticService(journal,execute)
   listener=Listener(gate/'relay.sock',service);(gate/'relay.sock').chmod(0o666)
   thread=threading.Thread(target=listener.serve,daemon=True);thread.start()
   ident=batch.start('goose')
   if os.environ.get('SFACTORY_FIXTURE_HOLD')=='1':
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
     logs=docker('logs',ident)
     if 'FIXTURE_WORKER_HOLD' in logs.stdout and service.phase=='done':break
     time.sleep(.1)
    else:raise RuntimeError('hold handshake unavailable')
    print('FIXTURE_BATCH_HOLD',flush=True)
    time.sleep(90)
   if negative:
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
     with service.lock:
      rejected=transport.turn==1 and service.phase=='inference_unknown' and fence.read()['stage']=='unknown0'
     if rejected:break
     time.sleep(.1)
    else:raise RuntimeError('negative control did not reject')
    if (manifest/'executor.exec').exists():raise RuntimeError('negative control invoked writer')
   else:
    status=subprocess.run(['/usr/bin/docker','--host','unix:///run/docker.sock','wait',ident],env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'},capture_output=True,text=True,timeout=90,check=True).stdout.strip();logs=docker('logs',ident)
    if status!='0' or 'PASS: Linux Goose completed host-relay tool exchange' not in logs.stdout:
     if recorded:
      print('GOOSE_CONTAINER_DIAGNOSTIC status='+status+' stdout_bytes='+str(len(logs.stdout.encode()))+' stderr_bytes='+str(len(logs.stderr.encode()))+' module_error='+str('ModuleNotFoundError' in logs.stderr)+' permission_error='+str('PermissionError' in logs.stderr)+' timeout_error='+str('TimeoutExpired' in logs.stderr),flush=True)
      for line in logs.stdout.splitlines():
       if line.startswith('GOOSE_DIAGNOSTIC '):print(line,flush=True)
     raise RuntimeError('Goose failed')
    if service.phase!='done':raise RuntimeError('conversation incomplete')
    if (os.environ.get('SFACTORY_FENCE_PREFLIGHT')=='1' or writer) and fence.read()['stage']!='done':raise RuntimeError('fence incomplete')
   if 'SFACTORY_CAPTURE_INITIAL' in os.environ:
    capture=os.environ['SFACTORY_CAPTURE_INITIAL'];fd=os.open(capture,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
     with os.fdopen(fd,'w') as output:json.dump(service.initial,output,separators=(',',':'));output.flush();os.fsync(output.fileno())
    except Exception:raise RuntimeError('initial capture unavailable') from None
   if not writer:print('PASS: actual Linux Goose -> UID-gated host -> batch-owned isolated executor -> disposable journal',flush=True)
  finally:
   if listener:listener.close()
   if thread:thread.join(timeout=5)
   batch.stop()
   if writer:check_original_fence()
  if writer:
   path=pathlib.Path(candidate)
   if recorded:
    if any(path.iterdir()) or (manifest/'executor.exec').exists():raise RuntimeError('offline diagnostic had effects')
    print('PASS: offline recorded response with mock writer and owned-root teardown',flush=True)
   elif negative:
    if any(path.iterdir()):raise RuntimeError('negative control wrote candidate')
    print('PASS: synthetic Goose rejected '+negative+' before writer and cleaned owned roots',flush=True)
   else:
    if {entry.name for entry in path.iterdir()}!={'hello.py','test_hello.py'} or (path/'hello.py').read_bytes()!=b'print(1)\n' or (path/'test_hello.py').read_bytes()!=b'pass\n':raise RuntimeError('candidate verification failed')
    print('PASS: synthetic Goose writer exchange and owned-root teardown',flush=True)

if __name__=='__main__':main()
