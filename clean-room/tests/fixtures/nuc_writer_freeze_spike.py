#!/usr/bin/env python3
"""NUC positive proof: actual fixed writer, durable success and revised freeze."""
import json,os,pathlib,subprocess,sys,tempfile,time,uuid
from docker_batch_guardian import Batch,APPROVED_SLICE,CGROUP_PATH
from nuc_file_contract import canonical_arguments
from nuc_int_loop_task import create
from nuc_int_loop_evaluator import freeze,store,system
from nuc_run_fence import RunFence
from nuc_original_create_guard import check as check_guard
IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'

def recover(task):
 Batch(task/'manifest',APPROVED_SLICE,CGROUP_PATH).stop()
 if not (task/'recovery.json').exists():store(task/'recovery.json',{'empty':True})

def drive(task):
 check_guard();baseline=json.loads((task/'task.json').read_text())['baseline'];source=task/'candidate';source.mkdir(mode=0o777);source.chmod(0o777)
 (source/'README.md').write_bytes((task/'repo'/'README.md').read_bytes());(source/'README.md').chmod(0o444)
 manifest=task/'manifest';manifest.mkdir(mode=0o700);fence_dir=task/'dispatch-fence';fence_dir.mkdir(mode=0o700)
 run=uuid.uuid4().hex;store(task/'run-scope.json',{'run':run,'baseline':baseline});fence=RunFence(fence_dir,run,baseline,create=True)
 batch=Batch(manifest,APPROVED_SLICE,CGROUP_PATH,source);here=pathlib.Path(__file__).resolve().parent
 arguments={'files':{'hello.py':'print(1)\n','test_hello.py':'pass\n'}}
 try:
  batch.prepare_fixed('goose',IMAGE,['-B','-c','import time;time.sleep(60)'],['--entrypoint','python3'])
  options=['--entrypoint','python3','--mount','type=bind,src='+str(here/'nuc_factory_write_files.py')+',dst=/factory-writer.py,readonly','--mount','type=bind,src='+str(here/'nuc_file_contract.py')+',dst=/nuc_file_contract.py,readonly']
  batch.prepare_fixed('executor',IMAGE,['-B','-c','import time;time.sleep(60)'],options,executor_kind='writer');batch.seal();batch.start('executor')
  call=fence.begin_inference(0,b'synthetic trusted request');fence.record_tool(call,b'synthetic provider response','tool',arguments);fence.begin_tool('tool',arguments)
  raw=batch.write_once(canonical_arguments(arguments));result=json.loads(raw)
  if result!={'status':'executed','exit_code':0,'stdout':'Both task files written.','stderr':''}:raise RuntimeError('writer failed')
  fence.record_tool_result('tool',json.dumps(result,separators=(',',':')).encode());call=fence.begin_inference(1,b'synthetic continuation');fence.record_final(call,b'synthetic final')
 finally:batch.stop()
 snapshot=freeze(task,source,manifest)
 if (snapshot/'snapshot'/'hello.py').read_bytes()!=b'print(1)\n':raise RuntimeError('snapshot differs')
 check_guard();store(task/'freeze-pass.json',{'snapshot':str(snapshot),'stage':fence.read()['stage'],'arguments_bound':True})
 os.close(fence.dirfd)

def main():
 check_guard()
 if 'populated 0' not in (CGROUP_PATH/'cgroup.events').read_text():raise RuntimeError('slice occupied')
 parent=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-freeze-positive-'));parent.chmod(0o700);task=parent/'task';create(task)
 script=pathlib.Path(__file__).resolve();unit='sfactory-freeze-'+uuid.uuid4().hex+'.service';store(task/'unit.json',{'unit':unit,'script':str(script)})
 command=['/usr/bin/systemd-run','--user','--unit='+unit,'--collect','--property=Description='+unit,'--property=RuntimeMaxSec=100s','--property=TimeoutStopSec=60s','--property=KillMode=control-group','--property=StandardOutput=append:'+str(task/'output.log'),'--property=StandardError=append:'+str(task/'output.log'),'--property=ExecStopPost=/usr/bin/python3 '+str(script)+' recover '+str(task),'/usr/bin/python3',str(script),'drive',str(task)]
 try:
  subprocess.run(command,capture_output=True,check=True,timeout=15)
  deadline=time.monotonic()+120
  while time.monotonic()<deadline:
   if system('show',unit,'-p','ActiveState','--value',check=False).stdout.strip() in ('','inactive','failed'):break
   time.sleep(.2)
  else:raise RuntimeError('deadline; retain '+str(task))
  if not (task/'freeze-pass.json').exists() or json.loads((task/'recovery.json').read_text())!={'empty':True}:raise RuntimeError('freeze proof failed; retain '+str(task))
  check_guard()
  print('PASS: actual isolated writer, durable done/fixed receipt, generation/baseline/argument-bound exact snapshot; manager cleanup verified; '+str(task),flush=True)
 finally:
  if system('show',unit,'-p','LoadState','--value',check=False).stdout.strip() not in ('','not-found'):
   if system('show',unit,'-p','Description','--value').stdout.strip()!=unit or str(script) not in system('show',unit,'-p','ExecStart','--value').stdout:raise RuntimeError('unit identity unresolved')
   system('stop',unit)

if __name__=='__main__':
 if len(sys.argv)>1:{'drive':drive,'recover':recover}[sys.argv[1]](pathlib.Path(sys.argv[2]))
 else:main()
