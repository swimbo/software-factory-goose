#!/usr/bin/env python3
"""Brake a synthetic real-Goose batch after killing its owned relay/journal unit."""
import pathlib, runpy, subprocess, sys
HERE=pathlib.Path(__file__).resolve().parent
base=runpy.run_path(str(HERE/'nuc_batch_authenticated_brake_spike.py'))['script']
base=base.replace("server=None; batch=None; clients=[]; complete=False", "server=None; batch=None; clients=[]; complete=False; unit=None; unit_attempted=False")
base=base.replace("manifest=runtime/'manifest'; manifest.mkdir(mode=0o700)", "manifest=runtime/'manifest'")
a=base.index(' batch=Batch(manifest,SLICE,CG)'); b=base.index(" sock=runtime/'brake.sock'",a)
replacement=r''' code=pathlib.Path('/tmp/sfactory-tool-relay-code.f6O9xEoS'); driver=code/'nuc_tool_relay_journal.py'; journal=root/'journal'; journal.mkdir(mode=0o700)
 unit='sfactory-brake-relay-'+uuid.uuid4().hex+'.service'; log=root/'unit.log'
 prior=subprocess.run(['systemctl','--user','show',unit,'-p','LoadState','--value'],capture_output=True,text=True,timeout=8)
 if prior.stdout.strip() not in ('','not-found'): raise RuntimeError('unit collision')
 unit_attempted=True
 subprocess.run(['systemd-run','--user','--unit='+unit,'--collect','--property=Description='+unit,'--property=RuntimeMaxSec=180s','--property=TimeoutStopSec=30s','--property=KillMode=control-group','--property=StandardOutput=append:'+str(log),'--property=StandardError=append:'+str(log),'--setenv=SFACTORY_FIXTURE_GOOSE_BATCH=1','--setenv=SFACTORY_FIXTURE_HOLD=1','--setenv=SFACTORY_BATCH_ROOT='+str(runtime),'--setenv=SFACTORY_JOURNAL_ROOT='+str(journal),'/usr/bin/python3',str(driver)],capture_output=True,text=True,check=True,timeout=10)
 deadline=time.monotonic()+100
 while time.monotonic()<deadline:
  if log.exists() and 'FIXTURE_BATCH_HOLD' in log.read_text(errors='replace'): break
  time.sleep(.05)
 else: raise RuntimeError('synthetic relay did not reach hold')
 batch=Batch(manifest,SLICE,CG); ids=[batch.read(role+'.manifest')['id'] for role in ('goose','executor')]
 if len(set(ids))!=2 or 'populated 1' not in (CG/'cgroup.events').read_text(): raise RuntimeError('positive batch control missing')
'''
base=base[:a]+replacement+base[b:]
needle=" # Hold the actual family lock across an authenticated request. Closure is"
kill=r''' # Stop only this verified task-owned journal/relay unit. No ExecStopPost
 # is configured, so the authenticated brake must clean the Docker roots.
 desc=subprocess.run(['systemctl','--user','show',unit,'-p','Description','--value'],capture_output=True,text=True,check=True,timeout=8).stdout.strip()
 command=subprocess.run(['systemctl','--user','show',unit,'-p','ExecStart','--value'],capture_output=True,text=True,check=True,timeout=8).stdout
 if desc!=unit or str(driver) not in command: raise RuntimeError('unit identity unresolved')
 subprocess.run(['systemctl','--user','kill','--kill-whom=all','--signal=SIGKILL',unit],capture_output=True,text=True,check=True,timeout=8)
 deadline=time.monotonic()+15
 while time.monotonic()<deadline:
  state=subprocess.run(['systemctl','--user','show',unit,'-p','ActiveState','--value'],capture_output=True,text=True,timeout=8).stdout.strip()
  if state in ('','inactive','failed'): break
  time.sleep(.05)
 else: raise RuntimeError('task relay unit still active')
 if 'populated 1' not in (CG/'cgroup.events').read_text(): raise RuntimeError('roots did not survive relay stop')
 from docker_owner_guardian import DisposableContainer
 for role in ('goose','executor'):
  record=batch.read(role+'.manifest'); owner=DisposableContainer(record['token']); owner.ident=record['id']; obj=owner.inspect(record['id'])
  if obj is None or obj['HostConfig']['CgroupParent']!=SLICE or (role=='goose' and not obj['State']['Running']): raise RuntimeError('owned root did not survive relay stop')
'''
base=base.replace(needle,kill+needle)
base=base.replace(" errors=[]\n if batch is not None:",r''' errors=[]
 if unit_attempted:
  try:
   load=subprocess.run(['systemctl','--user','show',unit,'-p','LoadState','--value'],capture_output=True,text=True,timeout=8).stdout.strip()
   if load not in ('','not-found'):
    desc=subprocess.run(['systemctl','--user','show',unit,'-p','Description','--value'],capture_output=True,text=True,check=True,timeout=8).stdout.strip()
    command=subprocess.run(['systemctl','--user','show',unit,'-p','ExecStart','--value'],capture_output=True,text=True,check=True,timeout=8).stdout
    if desc!=unit or str(driver) not in command: raise RuntimeError('unit identity unresolved')
    subprocess.run(['systemctl','--user','stop',unit],capture_output=True,text=True,check=True,timeout=40)
  except Exception as e: errors.append('unit '+str(e))
 if batch is None and manifest.exists():
  try: batch=Batch(manifest,SLICE,CG)
  except Exception as e: errors.append('manifest '+str(e))
 if batch is not None:''')
base=base.replace('PASS: UID/key/target denials; authenticated busy stop durably closed admission; both exact roots removed; same worker slice empty','PASS: synthetic Goose relay/journal stopped; UID/key/target denials; authenticated busy stop closed admission; both roots removed; slice empty')
base=base.replace('LIMIT: fixture authority; no actual relay outage, host/daemon-loss or production identity proof','LIMIT: synthetic relay only; no live gateway outage, host/daemon-loss or production identity proof')
if __name__=='__main__':
 result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=base,text=True,timeout=720)
 sys.exit(result.returncode)
