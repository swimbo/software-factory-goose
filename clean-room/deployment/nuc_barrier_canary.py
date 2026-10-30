#!/usr/bin/env python3
"""One uniquely owned NUC cgroup freeze / late Docker-start canary.

Runs a narrowly fixed root bridge; never points at an existing worker slice.
Retains the task directory and all unresolved objects after any ambiguity.
"""
import json, pathlib, subprocess, sys

REMOTE=r'''import json,os,pathlib,shutil,subprocess,sys,tempfile,time,uuid
ROOT=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-barrier-',dir='/tmp'));ROOT.chmod(0o700)
TOKEN=uuid.uuid4().hex; ROOT_CODE=__ROOT_SCRIPT__
BRIDGE='sfactory-barrier-bridge-'+TOKEN; LABEL='org.software-factory.barrier-bridge'; IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
def cmd(*args,check=True,timeout=15):return subprocess.run(list(args),capture_output=True,text=True,check=check,timeout=timeout,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'})
def inspect(target):
 r=cmd('/usr/bin/docker','--host','unix:///run/docker.sock','inspect',target,check=False)
 if r.returncode:
  if 'no such object' in r.stderr.lower():return None
  raise RuntimeError('bridge inspection unknown')
 o=json.loads(r.stdout)[0]
 if o['Name']!='/'+BRIDGE or (o['Config']['Labels'] or {}).get(LABEL)!=TOKEN:raise RuntimeError('bridge identity mismatch')
 if len(target)==64 and o['Id']!=target:raise RuntimeError('bridge full ID mismatch')
 return o
record=ROOT/'bridge-intent.json'
with open(record,'x') as f:json.dump({'name':BRIDGE,'token':TOKEN},f);f.flush();os.fsync(f.fileno())
fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
ident=None; complete=False
try:
 boot='import os;os.chroot("/host");os.chdir("/");os.execve("/usr/bin/python3",["/usr/bin/python3","-I","-B","-c",'+repr(ROOT_CODE)+','+repr(str(ROOT))+'],{"PATH":"/usr/bin:/bin","HOME":"/nonexistent"})'
 result=cmd('/usr/bin/docker','--host','unix:///run/docker.sock','create','--name',BRIDGE,'--label',LABEL+'='+TOKEN,'--network','none','--read-only','--cap-drop','ALL','--cap-add','SYS_CHROOT','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges','--pid','host','--cgroupns','host','--pids-limit','32','--memory','96m','--user','0:0','--pull','never','--mount','type=bind,src=/,dst=/host','--entrypoint','python3',IMAGE,'-I','-B','-c',boot,timeout=20)
 ident=result.stdout.strip()
 if len(ident)!=64 or any(x not in '0123456789abcdef' for x in ident):raise RuntimeError('bridge ID unknown')
 obj=inspect(ident)
 if obj is None or obj['State']['Status']!='created' or obj['State']['Running']:raise RuntimeError('bridge not created')
 hc=obj['HostConfig']; mounts=obj['Mounts']
 if obj['Image']!=IMAGE or obj['Config']['User']!='0:0' or hc['NetworkMode']!='none' or not hc['ReadonlyRootfs'] or hc['Privileged'] or hc['PidMode']!='host' or hc['CgroupnsMode']!='host' or set(hc['CapDrop'] or [])!={'ALL'} or {c.removeprefix('CAP_') for c in (hc['CapAdd'] or [])}!={'SYS_CHROOT','DAC_OVERRIDE'} or 'no-new-privileges' not in (hc['SecurityOpt'] or []) or len(mounts)!=1 or mounts[0]['Source']!='/' or mounts[0]['Destination']!='/host' or not mounts[0]['RW']:
  raise RuntimeError('bridge configuration mismatch')
 with open(ROOT/'bridge-manifest.json','x') as f:json.dump({'name':BRIDGE,'token':TOKEN,'id':ident},f);f.flush();os.fsync(f.fileno())
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 r=cmd('/usr/bin/docker','--host','unix:///run/docker.sock','start','-a',ident,check=False,timeout=170)
 print(r.stdout,end='');print(r.stderr,end='',file=sys.stderr)
 if r.returncode!=0:raise RuntimeError('root canary failed or remains unresolved')
 obj=inspect(ident)
 if obj is None or obj['State']['Running']:raise RuntimeError('bridge not stopped')
 lines=[line[7:] for line in r.stdout.splitlines() if line.startswith('RESULT ')]
 if len(lines)!=1 or len(lines[0])>2048:raise RuntimeError('root outcome unavailable')
 result=json.loads(lines[0])
 if result.get('state') not in ('canary_passed','canary_failed','canary_inconclusive'):raise RuntimeError('root canary did not verify closure')
 with open(ROOT/'outcome-received.json','x') as f:json.dump(result,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 cmd('/usr/bin/docker','--host','unix:///run/docker.sock','rm',ident)
 if inspect(ident) is not None:raise RuntimeError('bridge removal unverified')
 complete=True
 if result['state']!='canary_passed':raise RuntimeError('late-start freeze canary failed')
finally:
 if complete:print('CANARY_RECORD '+str(ROOT),flush=True)
 else:print('RETAINED '+str(ROOT)+' bridge='+str(ident or BRIDGE),file=sys.stderr,flush=True)
'''
ROOT_SCRIPT=r'''import json,os,pathlib,subprocess,sys,time,uuid
R=pathlib.Path(sys.argv[1]); T=uuid.uuid4().hex; SLICE='sfactory'+T+'.slice'; UNIT='sfactory'+T+'-anchor.service'; CG=pathlib.Path('/sys/fs/cgroup')/SLICE
D=['/usr/bin/docker','--host','unix:///run/docker.sock']; IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'; LABEL='org.software-factory.barrier-worker'
GUARD='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062'; GT='224a71d2db764249aa6cade3c1b39c80'
def run(*args,check=True,timeout=15):
 env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'}
 if args[0] in ('/usr/bin/systemctl','/usr/bin/systemd-run'):env['SYSTEMD_IN_CHROOT']='0'
 r=subprocess.run(list(args),capture_output=True,text=True,check=False,timeout=timeout,env=env)
 if check and r.returncode:
  print('FIXED_COMMAND_FAILURE '+json.dumps({'program':pathlib.Path(args[0]).name,'returncode':r.returncode,'stderr':r.stderr[:1024]}),flush=True)
  raise RuntimeError('fixed command failed')
 return r
def docker(*args,check=True,timeout=15):return run(*D,*args,check=check,timeout=timeout)
def syncfile(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(R,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def state(path):return dict(line.split() for line in path.read_text().splitlines())
def guard():
 info=json.loads(docker('info','--format','{{json .}}').stdout);pid=run('/usr/bin/systemctl','show','docker.service','-p','MainPID','--value').stdout.strip();commit=docker('version','--format','{{.Server.GitCommit}}').stdout.strip();o=json.loads(docker('inspect',GUARD).stdout)[0]
 if info.get('ID')!='56d25a60-5f64-4212-b904-e750067ac6a5' or pid!='2145' or commit!='3ce5872' or o['Id']!=GUARD or o['Name']!='/sf-owner-'+GT or (o['Config']['Labels'] or {}).get('org.software-factory.escape-spike')!=GT or o['State']['Status']!='created' or o['State']['Pid']!=0:raise RuntimeError('existing guard changed')
def wait(pred,seconds=10):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if pred():return
  time.sleep(.05)
 raise RuntimeError('deadline exceeded')
def inspect(ident,name,token):
 data=json.loads(docker('inspect',ident).stdout)
 if len(data)!=1:raise RuntimeError('container identity ambiguous')
 obj=data[0]
 if obj['Id']!=ident or obj['Name']!='/'+name or (obj['Config']['Labels'] or {}).get(LABEL)!=token or obj['HostConfig']['CgroupParent']!=SLICE:raise RuntimeError('container binding mismatch')
 return obj
def create(which):
 token=uuid.uuid4().hex;name='sfactory-barrier-'+which+'-'+token
 syncfile(R/(which+'-intent.json'),{'role':which,'name':name,'token':token,'slice':SLICE,'slice_inode':inode})
 source=R/(which+'.S');binary=R/(which+'.bin')
 source.write_text(' .global _start\n .text\n_start:\n mov $257,%rax\n mov $-100,%rdi\n lea path(%rip),%rsi\n mov $193,%rdx\n mov $438,%r10\n syscall\n test %rax,%rax\n js fail\n mov %rax,%rdi\n mov $1,%rax\n lea value(%rip),%rsi\n mov $1,%rdx\n syscall\n mov $35,%rax\n lea delay(%rip),%rdi\n xor %rsi,%rsi\n syscall\nfail:\n mov $60,%rax\n xor %rdi,%rdi\n syscall\n .section .rodata\npath: .asciz "/marker/ROLE"\nvalue: .ascii "x"\n .align 8\ndelay: .quad 30,0\n'.replace('ROLE',which))
 run('/usr/bin/cc','-nostdlib','-static','-Wl,-e,_start','-o',str(binary),str(source),timeout=20);binary.chmod(0o555)
 r=docker('create','--name',name,'--label',LABEL+'='+token,'--cgroup-parent',SLICE,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','16','--memory','64m','--cpus','0.1','--user','65534:65534','--pull','never','--mount','type=bind,src='+str(R/'marker')+',dst=/marker','--mount','type=bind,src='+str(binary)+',dst=/probe,readonly','--entrypoint','/probe',IMAGE,timeout=15)
 ident=r.stdout.strip()
 if len(ident)!=64 or any(c not in '0123456789abcdef' for c in ident):raise RuntimeError('unresolved created ID')
 o=inspect(ident,name,token)
 if o['State']['Status']!='created' or o['State']['Running']:raise RuntimeError('not safely created')
 syncfile(R/(which+'-manifest.json'),{'role':which,'id':ident,'name':name,'token':token,'slice':SLICE,'slice_inode':inode})
 return ident,name,token

guard();syncfile(R/'task-intent.json',{'slice':SLICE,'anchor':UNIT,'token':T})
(R/'marker').mkdir(mode=0o777);(R/'marker').chmod(0o777)
if run('/usr/bin/systemctl','show',UNIT,'-p','LoadState','--value',check=False).stdout.strip() not in ('','not-found'):raise RuntimeError('anchor collision')
if CG.exists():raise RuntimeError('slice collision')
run('/usr/bin/systemd-run','--unit='+UNIT,'--slice='+SLICE,'--property=Description='+UNIT,'--property=RuntimeMaxSec=180s','/usr/bin/sleep','180',timeout=15)
wait(CG.exists); inode=CG.stat().st_ino
syncfile(R/'slice.json',{'slice':SLICE,'inode':inode,'anchor':UNIT})
positive=create('positive'); late=create('late')
docker('start',positive[0]);wait((R/'marker'/'positive').exists)
o=inspect(*positive)
if not o['State']['Running']:raise RuntimeError('positive marker lacks live control')
docker('kill',positive[0]);inspect(*positive);docker('rm',positive[0])
syncfile(R/'closed.json',{'slice':SLICE,'inode':inode,'late_id':late[0]})
with open(CG/'cgroup.freeze','w') as f:f.write('1')
wait(lambda:state(CG/'cgroup.events').get('frozen')=='1')
if CG.stat().st_ino!=inode:raise RuntimeError('slice replaced')
proc=subprocess.Popen(D+['start',late[0]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'})
end=time.monotonic()+5; seen=False;thawed=False;scope_inode=None;frozen_live=False
scope=CG/('docker-'+late[0]+'.scope')
while time.monotonic()<end:
 if (R/'marker'/'late').exists():seen=True
 if state(CG/'cgroup.events').get('frozen')!='1':thawed=True
 if scope.exists():
  if scope.is_symlink() or scope.resolve(strict=True)!=scope:raise RuntimeError('scope path changed')
  current=scope.stat().st_ino
  if scope_inode is not None and scope_inode!=current:raise RuntimeError('scope identity changed')
  scope_inode=current; event=state(scope/'cgroup.events')
  if event.get('frozen')=='1' and event.get('populated')=='1':frozen_live=True
 time.sleep(.02)
observation={'late_id':late[0],'late_marker':seen,'thawed_observed':thawed,'scope_inode':scope_inode,'scope_frozen_populated':frozen_live,'rpc_returned_during_window':proc.poll() is not None,'slice_inode':inode}
syncfile(R/'observation.json',observation)
print('OBSERVATION '+json.dumps(observation),flush=True)
# Kill only this task-owned protected subtree, keeping the freeze in force.
guard()
if CG.stat().st_ino!=inode:raise RuntimeError('slice identity changed before kill')
with open(CG/'cgroup.kill','w') as f:f.write('1')
seen=seen or (R/'marker'/'late').exists()
try:out,err=proc.communicate(timeout=15)
except subprocess.TimeoutExpired:raise RuntimeError('late start RPC unresolved; frozen subtree retained')
syncfile(R/'start-result.json',{'returncode':proc.returncode,'stderr':err[:1024]})
wait(lambda:state(CG/'cgroup.events').get('populated')=='0',15)
if CG.stat().st_ino!=inode:raise RuntimeError('slice identity changed')
seen=seen or (R/'marker'/'late').exists()
obj=inspect(*late)
if obj['State']['Running']:raise RuntimeError('late container still running')
if state(CG/'cgroup.events').get('frozen')!='1':raise RuntimeError('freeze not retained after kill')
guard()
docker('rm',late[0])
absent=docker('inspect',late[0],check=False)
if absent.returncode==0 or 'no such object' not in absent.stderr.lower():raise RuntimeError('late removal unresolved')
if CG.stat().st_ino!=inode or state(CG/'cgroup.events').get('frozen')!='1' or state(CG/'cgroup.events').get('populated')!='0':raise RuntimeError('post-removal frozen empty proof missing')
seen=seen or (R/'marker'/'late').exists();guard()
syncfile(R/'removed.json',{'late_id':late[0],'slice_inode':inode,'removed_nonforce':True,'frozen':True,'populated':0})
# No RPC remains pending and no owned tasks remain before manager cleanup.
desc=run('/usr/bin/systemctl','show',UNIT,'-p','Description','--value').stdout.strip()
group=run('/usr/bin/systemctl','show',UNIT,'-p','ControlGroup','--value').stdout.strip()
if desc!=UNIT or group not in ('','/'+SLICE+'/'+UNIT):raise RuntimeError('anchor identity unresolved')
allowed={UNIT,'docker-'+positive[0]+'.scope','docker-'+late[0]+'.scope'}
if any(p.name not in allowed for p in CG.iterdir() if p.is_dir()):raise RuntimeError('unexpected subtree retained')
run('/usr/bin/systemctl','stop',UNIT)
run('/usr/bin/systemctl','stop',SLICE)
guard()
outcome={'state':('canary_failed' if seen or thawed else 'canary_passed' if frozen_live else 'canary_inconclusive'),'late_marker':seen,'thawed_observed':thawed,'positive_marker':True,'start_returncode':proc.returncode,'scope_inode':scope_inode,'scope_frozen_populated':frozen_live}
syncfile(R/'outcome.json',outcome)
print('RESULT '+json.dumps(outcome),flush=True)
'''
if __name__=='__main__':
 source=REMOTE.replace('__ROOT_SCRIPT__',repr(ROOT_SCRIPT));compile(source,'<remote>','exec');compile(ROOT_SCRIPT,'<root>','exec')
 p=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=source,text=True,timeout=210)
 sys.exit(p.returncode)
