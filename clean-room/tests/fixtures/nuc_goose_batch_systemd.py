#!/usr/bin/env python3
"""Synthetic Goose, relay and journal under an owned systemd recovery unit."""
import os,pathlib,shutil,subprocess,sys,tempfile,time,uuid
ROOT=pathlib.Path('/tmp/sfactory-tool-relay-code.f6O9xEoS')
SLICE='sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0-worker.slice'
CG=pathlib.Path('/sys/fs/cgroup/sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice')/SLICE
sys.path.insert(0,str(ROOT))
from docker_batch_guardian import Batch
from docker_owner_guardian import DisposableContainer

def system(*args,check=True,timeout=60):
 return subprocess.run(['systemctl','--user',*args],capture_output=True,text=True,check=check,timeout=timeout)

def wait_for(fn,seconds):
 deadline=time.monotonic()+seconds
 while time.monotonic()<deadline:
  value=fn()
  if value:return value
  time.sleep(.05)
 raise RuntimeError('fixture readiness or recovery deadline')

if 'populated 0' not in (CG/'cgroup.events').read_text(): raise RuntimeError('worker slice already occupied')
temp=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-goose-systemd-',dir=ROOT)); temp.chmod(0o700)
batchroot=temp/'batch'; batchroot.mkdir(mode=0o700); journal=temp/'journal'; journal.mkdir(mode=0o700)
unit='sfactory-'+uuid.uuid4().hex+'.service'; attempted=False; complete=False
recovery=temp/'recovery.py'
recovery.write_text("""import pathlib,sys
sys.path.insert(0,%r)
from docker_batch_guardian import Batch
root=pathlib.Path(sys.argv[1]); outcome=pathlib.Path(sys.argv[2])
try:
 b=Batch(root/'manifest',%r,%r); b.stop(); outcome.write_text('OK')
except Exception as e:
 outcome.write_text('ERROR '+str(e)); raise
""" %(str(ROOT),SLICE,str(CG)))
try:
 prior=system('show',unit,'-p','LoadState','--value',check=False)
 if prior.stdout.strip() not in ('','not-found'): raise RuntimeError('unit collision')
 output=temp/'output.log'; attempted=True
 cmd=['systemd-run','--user','--unit='+unit,'--collect','--property=Description='+unit,
  '--property=RuntimeMaxSec=120s','--property=TimeoutStopSec=60s','--property=KillMode=control-group',
  '--property=StandardOutput=append:'+str(output),'--property=StandardError=append:'+str(output),
  '--property=ExecStopPost=/usr/bin/python3 '+str(recovery)+' '+str(batchroot)+' '+str(temp/'recovered'),
  '--setenv=SFACTORY_FIXTURE_GOOSE_BATCH=1','--setenv=SFACTORY_FIXTURE_HOLD=1',
  '--setenv=SFACTORY_BATCH_ROOT='+str(batchroot),'--setenv=SFACTORY_JOURNAL_ROOT='+str(journal),
  '/usr/bin/python3',str(ROOT/'nuc_tool_relay_journal.py')]
 subprocess.run(cmd,capture_output=True,text=True,check=True,timeout=10)
 wait_for(lambda: output.exists() and 'FIXTURE_BATCH_HOLD' in output.read_text(errors='replace'),100)
 b=Batch(batchroot/'manifest',SLICE,CG); ids=[]
 for role in ('goose','executor'):
  record=b.read(role+'.manifest'); ids.append(record['id']); owner=DisposableContainer(record['token']); owner.ident=record['id']
  obj=owner.inspect(record['id'])
  if obj is None or obj['HostConfig']['CgroupParent']!=SLICE: raise RuntimeError('root identity missing')
 if len(set(ids))!=2 or 'populated 1' not in (CG/'cgroup.events').read_text(): raise RuntimeError('two-root live control failed')
 desc=system('show',unit,'-p','Description','--value').stdout.strip(); command=system('show',unit,'-p','ExecStart','--value').stdout
 if desc!=unit or str(ROOT/'nuc_tool_relay_journal.py') not in command: raise RuntimeError('unit identity mismatch')
 system('kill','--kill-whom=main','--signal=SIGKILL',unit,timeout=10)
 wait_for(lambda:(temp/'recovered').exists(),55)
 result=(temp/'recovered').read_text()
 if result!='OK': raise RuntimeError('batch recovery unresolved: '+result)
 if not b.stop() or 'populated 0' not in (CG/'cgroup.events').read_text(): raise RuntimeError('independent empty observation missing')
 wait_for(lambda: system('show',unit,'-p','ActiveState','--value',check=False).stdout.strip() in ('','inactive','failed'),15)
 print('PASS: actual synthetic Goose/relay/journal reached hold; systemd owner SIGKILL invoked batch recovery; two owned roots removed and slice populated 0',flush=True)
 complete=True
finally:
 if attempted:
  load=system('show',unit,'-p','LoadState','--value',check=False).stdout.strip()
  if load not in ('','not-found'):
   desc=system('show',unit,'-p','Description','--value').stdout.strip(); command=system('show',unit,'-p','ExecStart','--value').stdout
   if desc!=unit or str(ROOT/'nuc_tool_relay_journal.py') not in command: raise RuntimeError('unit identity unresolved; retain '+str(temp))
   system('stop',unit,check=True)
 if complete: shutil.rmtree(temp)
 else: print('RETAINED '+str(temp),file=sys.stderr,flush=True)
print('LIMIT: synthetic provider; no live Bifrost, actual untrusted stdin, authenticated brake or manager/daemon loss proof')
