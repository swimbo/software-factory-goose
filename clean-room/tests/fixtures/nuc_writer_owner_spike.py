#!/usr/bin/env python3
"""No-provider NUC writer invocation and supervised owner-loss canaries."""
import pathlib, subprocess, sys
H=pathlib.Path(__file__).resolve().parent
names=['docker_batch_guardian.py','docker_owner_guardian.py','nuc_factory_write_files.py','nuc_file_contract.py']
files={n:(H/n).read_text() for n in names}
files['docker_owned_escape_spike.py']='IMAGE="unused"\nLABEL="org.software-factory.escape-spike"\nMAIN="unused"\n'
DRIVER=r'''import json,os,pathlib,shutil,subprocess,sys,tempfile,time,uuid
SLICE='sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0-worker.slice'; CG=pathlib.Path('/sys/fs/cgroup/sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice')/SLICE
IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'; files=__FILES__

def run(*a,check=True):return subprocess.run(a,capture_output=True,text=True,timeout=15,check=check)
def system(*a,check=True):return run('systemctl','--user',*a,check=check)
def guard():
 ident='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062';token='224a71d2db764249aa6cade3c1b39c80'
 info=json.loads(run('/usr/bin/docker','--host','unix:///run/docker.sock','info','--format','{{json .}}').stdout)
 pid=run('systemctl','show','docker.service','-p','MainPID','--value').stdout.strip()
 objs=json.loads(run('/usr/bin/docker','--host','unix:///run/docker.sock','inspect',ident).stdout)
 if len(objs)!=1:raise RuntimeError('retained original identity unavailable')
 obj=objs[0]
 if info.get('ID')!='56d25a60-5f64-4212-b904-e750067ac6a5' or pid!='2145' or obj.get('Id')!=ident or obj.get('Name')!='/sf-owner-'+token or (obj.get('Config',{}).get('Labels') or {}).get('org.software-factory.escape-spike')!=token or obj.get('State',{}).get('Status')!='created' or obj.get('State',{}).get('Pid')!=0 or obj.get('HostConfig',{}).get('CgroupParent')!=SLICE:
  raise RuntimeError('retained original fence changed')
def wait(pred,secs=30):
 end=time.monotonic()+secs
 while time.monotonic()<end:
  if pred():return
  time.sleep(.04)
 raise RuntimeError('readiness deadline')
guard()
if 'populated 0' not in (CG/'cgroup.events').read_text():raise RuntimeError('worker slice occupied')
for mode in ('success','partial','lostack','cleanup_failure'):
 guard()
 root=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-writer-owner-')); root.chmod(0o700); good=False; attempted=False
 data=root/'data';data.mkdir(mode=0o700); candidate=root/'candidate';candidate.mkdir(mode=0o777);candidate.chmod(0o777)
 for n,content in files.items():(root/n).write_text(content);(root/n).chmod(0o444)
 sys.path.insert(0,str(root)); from docker_batch_guardian import Batch
 b=Batch(data,SLICE,CG,candidate); inode=CG.stat().st_ino
 hooks=root/'hooks';hooks.mkdir(mode=0o755)
 (hooks/'sitecustomize.py').write_text("""import os,time\nold=os.link\ndef link(*a,**kw):\n result=old(*a,**kw)\n with open('/work/.hook-ready','w') as f:f.write('one linked')\n while True:time.sleep(1)\n return result\nos.link=link\n""");(hooks/'sitecustomize.py').chmod(0o444)
 maker=root/'maker.py'; maker.write_text("""import json,pathlib,sys,time\nfrom docker_batch_guardian import Batch\nroot=pathlib.Path(sys.argv[1]); mode=sys.argv[2]; b=Batch(root/'data',sys.argv[3],sys.argv[4],root/'candidate'); image=sys.argv[5]\nb.prepare_fixed('goose',image,['-u','-c','import time;time.sleep(90)'],['--entrypoint','python3'])\nopts=['--entrypoint','python3','--mount','type=bind,src='+str(root/'nuc_factory_write_files.py')+',dst=/factory-writer.py,readonly','--mount','type=bind,src='+str(root/'nuc_file_contract.py')+',dst=/nuc_file_contract.py,readonly','--workdir','/work']\nif mode=='partial':opts += ['--mount','type=bind,src='+str(root/'hooks')+',dst=/factory-hooks,readonly','--env','PYTHONPATH=/factory-hooks']\nb.prepare_fixed('executor',image,['-u','-c','import time;time.sleep(90)'],opts,executor_kind='writer');b.seal();b.start('goose');b.start('executor')\nfrom docker_owner_guardian import DisposableContainer\nfor role,cap in [('goose',512*1024*1024),('executor',128*1024*1024)]:\n record=b.read(role+'.manifest');owner=DisposableContainer(record['token']);owner.ident=record['id'];obj=owner.inspect(owner.ident)\n if obj['HostConfig']['Memory']!=cap or record.get('memory')!=cap:raise RuntimeError('role memory mismatch')\n pid=obj['State']['Pid']; lines=pathlib.Path('/proc/'+str(pid)+'/cgroup').read_text().splitlines(); path=next(x.split(':',2)[2] for x in lines if x.startswith('0::'))\n if int((pathlib.Path('/sys/fs/cgroup')/path.lstrip('/')/'memory.max').read_text().strip())!=cap:raise RuntimeError('kernel memory limit mismatch')\nrecord=b.read('executor.manifest');owner=DisposableContainer(record['token']);owner.ident=record['id'];obj=owner.inspect(owner.ident)\nmounts={m['Destination']:m for m in obj['Mounts']}\nfor target,source in [('/factory-writer.py',root/'nuc_factory_write_files.py'),('/nuc_file_contract.py',root/'nuc_file_contract.py')]:\n m=mounts.get(target)\n if not m or m['Type']!='bind' or m['RW'] or m['Source']!=str(source):raise RuntimeError('writer mount identity mismatch')\ntry:b.exec_once(b'{}')\nexcept RuntimeError:pass\nelse:raise RuntimeError('writer executor accepted shell mode')\npayload=json.dumps({'files':{'hello.py':'print(1)\\n','test_hello.py':'print(2)\\n'}},separators=(',',':')).encode()\nout=b.write_once(payload);(root/'writer-result').write_bytes(out);(root/'ready').write_text('ready');time.sleep(90)\n""")
 recovery=root/'recovery.py';recovery.write_text("""import pathlib,sys\nfrom docker_batch_guardian import Batch\nimport docker_owner_guardian as owner\nif sys.argv[4]=='cleanup_failure':\n original=owner.docker\n def fault(*args,**kwargs):\n  if args[0]=='kill':raise RuntimeError('injected owned cleanup failure')\n  return original(*args,**kwargs)\n owner.docker=fault\nr=pathlib.Path(sys.argv[1]); b=Batch(r/'data',sys.argv[2],sys.argv[3]);b.stop();(r/'recovered').write_text('verified')\n""")
 unit='sfactory-writer-'+uuid.uuid4().hex+'.service';output=root/'output.log'
 try:
  if system('show',unit,'-p','LoadState','--value',check=False).stdout.strip() not in ('','not-found'):raise RuntimeError('unit collision')
  attempted=True
  run('systemd-run','--user','--unit='+unit,'--collect','--property=Description='+unit,'--property=RuntimeMaxSec=120s','--property=TimeoutStopSec=60s','--property=KillMode=control-group','--property=StandardOutput=append:'+str(output),'--property=StandardError=append:'+str(output),'--property=ExecStopPost=/usr/bin/python3 '+str(recovery)+' '+str(root)+' '+SLICE+' '+str(CG)+' '+mode,'/usr/bin/python3',str(maker),str(root),mode,SLICE,str(CG),IMAGE)
  ready=candidate/'.hook-ready' if mode=='partial' else root/'ready';wait(ready.exists)
  if mode=='partial':
   if not (candidate/'hello.py').exists() or (candidate/'test_hello.py').exists():raise RuntimeError('partial link control missing')
  else:
   result=json.loads((root/'writer-result').read_text())
   if result.get('status')!='executed' or (candidate/'hello.py').read_text()!='print(1)\n' or (candidate/'test_hello.py').read_text()!='print(2)\n':raise RuntimeError('writer output unavailable')
   if {p.name for p in candidate.iterdir()}!={'hello.py','test_hello.py'}:raise RuntimeError('writer produced unexpected candidate entry')
  if not (data/'executor.exec').exists() or 'populated 1' not in (CG/'cgroup.events').read_text():raise RuntimeError('owned execution control missing')
  desc=system('show',unit,'-p','Description','--value').stdout.strip();command=system('show',unit,'-p','ExecStart','--value').stdout
  if desc!=unit or str(maker) not in command:raise RuntimeError('unit identity mismatch')
  system('kill','--kill-whom=main','--signal=SIGKILL',unit)
  if mode=='cleanup_failure':
   wait(lambda:system('show',unit,'-p','ActiveState','--value',check=False).stdout.strip() in ('','inactive','failed'),30)
   if (root/'recovered').exists() or 'populated 1' not in (CG/'cgroup.events').read_text():raise RuntimeError('cleanup failure falsely verified')
   if not Batch(data,SLICE,CG).stop():raise RuntimeError('fallback cleanup unresolved')
   if CG.stat().st_ino!=inode or 'populated 0' not in (CG/'cgroup.events').read_text():raise RuntimeError('fallback empty observation missing')
   guard();print('PASS cleanup_failure: failed cleanup withheld receipt; exact fallback cleanup emptied slice',flush=True);good=True
   continue
  wait((root/'recovered').exists,55)
  if (root/'recovered').read_text()!='verified' or CG.stat().st_ino!=inode or 'populated 0' not in (CG/'cgroup.events').read_text():raise RuntimeError('cleanup unresolved')
  wait(lambda:system('show',unit,'-p','ActiveState','--value',check=False).stdout.strip() in ('','inactive','failed'),15)
  if not Batch(data,SLICE,CG).stop():raise RuntimeError('idempotent cleanup failed')
  guard()
  try:b.write_once(b'{}')
  except RuntimeError:pass
  else:raise RuntimeError('writer replay admitted')
  print('PASS '+mode+': fixed writer/owner death; exact cleanup and empty slice; replay denied',flush=True);good=True
 finally:
  if attempted:
   load=system('show',unit,'-p','LoadState','--value',check=False).stdout.strip()
   if load not in ('','not-found'):
    desc=system('show',unit,'-p','Description','--value').stdout.strip();command=system('show',unit,'-p','ExecStart','--value').stdout
    if desc!=unit or str(maker) not in command:raise RuntimeError('unit identity unresolved; retain '+str(root))
    system('stop',unit)
  if not good and any((data/(role+'.intent')).exists() for role in ('goose','executor')):
   try:b.stop()
   except Exception as e:print('owned cleanup unresolved: '+str(e),file=sys.stderr,flush=True)
  guard()
  if good:shutil.rmtree(root)
  else:print('RETAINED '+str(root),file=sys.stderr,flush=True)
print('LIMIT: fixture no provider fence/evaluator; lostack is owner death after write result and before any durable tool-result receipt')
'''
script=DRIVER.replace('__FILES__',repr(files))
compile(script,'<remote>','exec')
if __name__=='__main__':
 result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=script,text=True,timeout=240)
 sys.exit(result.returncode)
