#!/usr/bin/env python3
"""Explicit single-run INT-LOOP driver; requires manager-owned supervision."""
import hashlib,json,os,pathlib,stat,subprocess,sys,threading,uuid
from docker_batch_guardian import Batch
from docker_owner_guardian import docker
from nuc_goose_relay_socket import Listener
from nuc_live_goose_service import LiveService
from nuc_bifrost_pinned_exec import PinnedDockerTransport
from nuc_run_fence import RunFence
from nuc_task_request_pin import TaskRequestPin
from nuc_original_create_guard import check as check_original_fence
from nuc_file_contract import canonical_arguments
from nuc_structured_file_relay import WRITE_TOOL
from nuc_goose_relay_batch import ROOT,GOOSE,EXEC,IMAGE,SLICE,CGROUP
TASK=pathlib.Path('/tmp/sfactory-real-int-loop-20261028')
TARGET='94f32c4f1399d74fffaa909c878422ee0f86bb31127e3c83c4c3dac4de03facc'
TARGET_IMAGE='sha256:d0b4708ace1aa175766f94afa715fd9bba3a1b56c1dc2afff15a21edf3ae4e2a'
DAEMON='56d25a60-5f64-4212-b904-e750067ac6a5'
PID=3519722
KEY='/home/bo/.hermes/bifrost/factory-secrets/software-factory-goose/credential'
SUFFIX=' Use exactly one factory write_files tool call to provide both files, then stop. Do not include any preamble before the tool call.'
MODELS={'ollama-cloud/deepseek-v4-pro:0813','ollama-cloud/deepseek-v4.1-flash:1017','deepseek-v4-pro:0813','deepseek-v4.1-flash:1017'}

def read_owned(path,limit,mode=None):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_size>limit or (mode is not None and stat.S_IMODE(st.st_mode)!=mode):raise RuntimeError('task bootstrap unavailable')
  data=os.read(fd,limit+1)
  if len(data)>limit:raise RuntimeError('task bootstrap unavailable')
  return data
 finally:os.close(fd)

def write_owned(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as out:json.dump(value,out,sort_keys=True,separators=(',',':'));out.flush();os.fsync(out.fileno())
 parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(parent)
 finally:os.close(parent)

def main():
 if sys.argv!=[sys.argv[0],'--live'] or os.getuid()!=1000 or os.environ.get('SFACTORY_LIVE_ATTEMPT')!='5':raise RuntimeError('explicit fresh task scope required')
 batch_root=pathlib.Path(os.environ['SFACTORY_BATCH_ROOT'])
 if batch_root.is_symlink() or batch_root.stat().st_uid!=1000 or stat.S_IMODE(batch_root.stat().st_mode)!=0o700:raise RuntimeError('manager scope unavailable')
 task=json.loads(read_owned(TASK/'task.json',65536));prompt=task['spec']+SUFFIX
 snapshot=json.loads(read_owned(TASK/'goose-initial-v2.json',65536,0o600))
 marker='\n<turn-context>\n';prior=snapshot['messages'][1]['content']
 if prior.count(marker)!=1:raise RuntimeError('trusted template unavailable')
 snapshot['messages'][1]['content']=prompt+marker+prior.split(marker,1)[1];snapshot['tools']=[WRITE_TOOL]
 pin=TaskRequestPin(snapshot,prompt);check_original_fence()
 # A fresh generation never resets or reuses the first attempt's unknown fence.
 run_root=TASK/'attempt5';run_root.mkdir(mode=0o700)
 work=run_root/'candidate-work';work.mkdir(mode=0o777);work.chmod(0o777)
 source=read_owned(TASK/'repo'/'README.md',32768);(work/'README.md').write_bytes(source);(work/'README.md').chmod(0o444)
 fence_root=run_root/'dispatch-fence';fence_root.mkdir(mode=0o700)
 run=uuid.uuid4().hex;fence=RunFence(fence_root,run,task['baseline'],create=True)
 write_owned(run_root/'initial-snapshot.json',snapshot)
 write_owned(run_root/'run-scope.json',{'run':run,'baseline':task['baseline'],'initial_sha256':hashlib.sha256(json.dumps(snapshot,separators=(',',':')).encode()).hexdigest(),'monetary_cap':None,'model':'auto','container':TARGET,'image':TARGET_IMAGE,'pid':PID,'daemon':DAEMON})
 transport=PinnedDockerTransport(container_id=TARGET,image_id=TARGET_IMAGE,pid=PID,daemon_id=DAEMON,credential_path=KEY)
 fixtures=batch_root/'fixtures';fixtures.mkdir(mode=0o755)
 for filename in ('nuc_goose_relay_worker.py','nuc_stream_contract.py'):
  contents=read_owned(ROOT/filename,65536);destination=fixtures/filename;destination.write_bytes(contents);destination.chmod(0o444)
 gate=batch_root/'gate';gate.mkdir(mode=0o711);manifest=batch_root/'manifest';manifest.mkdir(mode=0o700)
 for filename in ('nuc_factory_write_files.py','nuc_file_contract.py'):
  contents=read_owned(ROOT/filename,65536);destination=fixtures/filename;destination.write_bytes(contents);destination.chmod(0o444)
 batch=Batch(manifest,SLICE,CGROUP,candidate=str(work));listener=None;thread=None;complete=False
 try:
  wo=['--mount','type=bind,src='+GOOSE+',dst=/goose,readonly','--mount','type=bind,src='+str(fixtures)+',dst=/fixtures,readonly','--mount','type=bind,src='+str(gate)+',dst=/gate,readonly','--tmpfs','/work:rw,exec,nosuid,nodev,size=128m,mode=1777','--env','SFACTORY_TASK_PROMPT='+prompt,'--env','SFACTORY_LIVE_TASK=1','--env','SFACTORY_TOOL_MODE=write_files','--entrypoint','python3']
  eo=['--mount','type=bind,src='+str(fixtures/'nuc_factory_write_files.py')+',dst=/factory-writer.py,readonly','--mount','type=bind,src='+str(fixtures/'nuc_file_contract.py')+',dst=/nuc_file_contract.py,readonly','--workdir','/work','--entrypoint','python3']
  batch.prepare_fixed('goose',IMAGE,['-B','/fixtures/nuc_goose_relay_worker.py'],wo)
  batch.prepare_fixed('executor',IMAGE,['-B','-c','import time;time.sleep(240)'],eo,executor_kind='writer');batch.seal();batch.start('executor')
  def execute(arguments):return json.loads(batch.write_once(canonical_arguments(arguments)))
  service=LiveService(initial=snapshot,initial_validator=pin,allowed_models=MODELS,fence=fence,transport=transport,execute=execute,tool_mode='write_files')
  listener=Listener(gate/'relay.sock',service);(gate/'relay.sock').chmod(0o666);thread=threading.Thread(target=listener.serve,daemon=True);thread.start()
  ident=batch.start('goose');status=subprocess.run(['/usr/bin/docker','--host','unix:///run/docker.sock','wait',ident],env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'},capture_output=True,text=True,timeout=175,check=True).stdout.strip();logs=docker('logs',ident)
  if status!='0' or service.phase!='done' or 'PASS: Linux Goose completed host-relay tool exchange' not in logs.stdout:raise RuntimeError('task outcome unknown')
  write_owned(run_root/'provider-observations.json',service.observed)
  complete=True
 finally:
  if listener:listener.close()
  if thread:thread.join(timeout=5)
  batch.stop();check_original_fence()
 if complete:print('PASS: scoped live Goose writer completed and roots stopped; candidate awaits independent evaluation',flush=True)

if __name__=='__main__':main()
