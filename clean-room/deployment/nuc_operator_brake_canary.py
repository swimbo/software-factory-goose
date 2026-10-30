#!/usr/bin/env python3
"""Review-only root-stop positive/negative canary. Never run without reviewed install.

Creates only a fresh factory-prefixed target and does not depend on Docker. On
ambiguity it leaves the catalogue, closed record, unit and slice for inspection.
"""
import hashlib,json,os,pathlib,pwd,grp,re,socket,stat,subprocess,sys,time
EXPECTED='99236f262d181442e395a9f706e99856027fab7f069bcb6fefb6950b0c324443'
FRONT_EXPECTED='c18388b4e5b1b26cf986bdb893baff8ce6ecc49f229923ff3075ab1bb95af232'
SFCTL_EXPECTED='d83b2d93a8cc4b7fddce6c435bafbbdf2b4b2c925d52a713398c4282729f1c6e'
SFCTL='/usr/local/libexec/software-factory-goose/sfctl'
BRAKEUNIT='software-factory-goose-brake.socket'; BRAKESERVICE='software-factory-goose-brake.service'
HUMAN_KEY='/etc/software-factory-goose/operator-brake.key'
ROOT=pathlib.Path('/etc/software-factory-goose/tasks');STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
SOCKET='/run/software-factory-goose/root-stop.sock';SERVICE='software-factory-goose-root-stop.service';SOCKUNIT='software-factory-goose-root-stop.socket'
ALPH='0123456789ABCDEFGHJKMNPQRSTVWXYZ'
DROP_DIR=pathlib.Path('/etc/systemd/system/software-factory-goose-root-stop.service.d')
DROP=DROP_DIR/'10-no-docker.conf'
MASK_INTENT=STATE/'root-stop-mask-intent.json';MASK_RECEIPT=STATE/'root-stop-mask-receipt.json'
MASK='''[Service]\nInaccessiblePaths=-/run/docker.sock\nExecStartPre=/usr/bin/python3 -I -B -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(1); r=s.connect_ex('/run/docker.sock'); sys.exit(0 if r in (1,2,13,40,88) else 1)"\n'''
def new_id():
 n=(int(time.time()*1000)<<80)|int.from_bytes(os.urandom(10),'big');return ''.join(ALPH[(n>>shift)&31] for shift in range(125,-1,-5))
def run(*a,check=True,timeout=15):
 p=subprocess.run(a,capture_output=True,text=True,check=False,timeout=timeout,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0'})
 if check and p.returncode:raise RuntimeError('fixed operation failed: '+pathlib.Path(a[0]).name)
 return p
def system(*a,check=True):return run('/usr/bin/systemctl',*a,check=check)
def wait(pred,seconds=15):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if pred():return
  time.sleep(.05)
 raise RuntimeError('canary readiness unresolved')
def store(path,obj):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(obj,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def install_mask():
 metadata(DROP_DIR.parent,0o755)
 expected=hashlib.sha256(MASK.encode()).hexdigest()
 if DROP_DIR.exists() or DROP_DIR.is_symlink() or MASK_INTENT.exists() or MASK_RECEIPT.exists():
  # Only an exact completed installation of this same drop-in is reusable.
  for path in (MASK_INTENT,MASK_RECEIPT,DROP):
   st=path.lstat()
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=(0o644 if path==DROP else 0o600):raise RuntimeError('mask record identity mismatch')
  metadata(DROP_DIR,0o755)
  if {p.name for p in DROP_DIR.iterdir()}!={DROP.name} or DROP.read_text()!=MASK or json.loads(MASK_INTENT.read_text())!={'sha256':expected} or json.loads(MASK_RECEIPT.read_text())!={'sha256':expected,'status':'installed'}:raise RuntimeError('mask collision or partial installation')
 else:
  store(MASK_INTENT,{'sha256':expected})
  os.mkdir(DROP_DIR,0o755);os.chmod(DROP_DIR,0o755)
  fd=os.open(DROP_DIR,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
  fd=os.open(DROP_DIR.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
  fd=os.open(DROP,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
  with os.fdopen(fd,'w') as f:os.fchmod(f.fileno(),0o644);f.write(MASK);f.flush();os.fsync(f.fileno())
  fd=os.open(DROP_DIR,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
  store(MASK_RECEIPT,{'sha256':expected,'status':'installed'})
 system('daemon-reload')
 return expected
def guard():
 d=['/usr/bin/docker','--host','unix:///run/docker.sock'];x=json.loads(run(*d,'info','--format','{{json .}}').stdout);pid=system('show','docker.service','-p','MainPID','--value').stdout.strip();commit=run(*d,'version','--format','{{.Server.GitCommit}}').stdout.strip();o=json.loads(run(*d,'inspect','04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062').stdout)[0]
 if x.get('ID')!='56d25a60-5f64-4212-b904-e750067ac6a5' or pid!='2145' or commit!='3ce5872' or o['Id']!='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062' or o['Name']!='/sf-owner-224a71d2db764249aa6cade3c1b39c80' or o['State']['Status']!='created' or o['State']['Pid']!=0:raise RuntimeError('original guard changed')
def metadata(path,mode):
 s=path.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=mode:raise RuntimeError('untrusted deployment directory')
def preflight_succeeded(value):
 return value.count('{ path=')==1 and '{ path=/usr/bin/python3 ;' in value and re.search(r'\bcode=exited\s*;\s*status=0(?:/SUCCESS)?\s*\}',value) is not None
def peer(role,body):
 # systemd, not the root bridge, switches UID/GID for this fixed peer program.
 code="import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(8);s.connect('/run/software-factory-goose/root-stop.sock');s.sendall(sys.argv[1].encode());s.shutdown(socket.SHUT_WR);b=b''\nwhile True:\n x=s.recv(4096)\n if not x:break\n b+=x\n if len(b)>4096:raise RuntimeError('oversized')\nprint(b.decode())"
 if role not in ('sfgoose-control','sfgoose-brake'):raise RuntimeError('unsupported test peer')
 peer_unit='sfactory-stop-peer-'+new_id().lower()+'.service'
 if system('show',peer_unit,'-p','LoadState','--value',check=False).stdout.strip() not in ('','not-found'):raise RuntimeError('peer unit collision')
 return run('/usr/bin/systemd-run','--unit='+peer_unit,'--collect','--wait','--pipe','--property=User='+role,'--property=Group=sfgoose-brake','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=RuntimeMaxSec=15s','/usr/bin/python3','-I','-B','-c',code,json.dumps(body,separators=(',',':')),check=False,timeout=20)
def shared_snapshot():
 # Only inspect existing service states and existing container IDs/states.
 services={n:system('show',n,'-p','ActiveState','-p','MainPID').stdout for n in ('docker.service','hermes-dashboard.service','hermes-gateway.service')}
 containers=run('/usr/bin/docker','--host','unix:///run/docker.sock','ps','--no-trunc','--format','{{.ID}} {{.Names}}').stdout.splitlines()
 return {'services':services,'containers':sorted(containers)}

def checked_binary(path,expected):
 s=pathlib.Path(path).lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o755 or hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()!=expected:raise RuntimeError('installed canary binary mismatch')

def checked_brake_units():
 expected={'software-factory-goose-brake.socket':'9156dd4f32c175f8576a2658234295fa8154bd6d448f1205a667406026bb245a','software-factory-goose-brake.service':'08a835a79442383c893fd0b84eb19a049f1d45d341dec93efb41c880896e1f40'}
 for name,want in expected.items():
  p=pathlib.Path('/etc/systemd/system')/name;st=p.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o644 or hashlib.sha256(p.read_bytes()).hexdigest()!=want:raise RuntimeError('brake unit identity mismatch')
  fragment=system('show',name,'-p','FragmentPath','--value').stdout.strip()
  drops=system('show',name,'-p','DropInPaths','--value').stdout.strip()
  if fragment!=str(p) or drops:raise RuntimeError('loaded brake unit differs')

def bo_cli(target,op,key):
 if op not in ('stop','status') or key not in (HUMAN_KEY, str(pathlib.Path('/etc/software-factory-goose')/('brake-canary-'+target+'.key'))):raise RuntimeError('invalid fixed canary invocation')
 unit='sfactory-brake-cli-'+new_id().lower()+'.service'
 if system('show',unit,'-p','LoadState','--value',check=False).stdout.strip() not in ('','not-found'):raise RuntimeError('CLI unit collision')
 return run('/usr/bin/systemd-run','--unit='+unit,'--collect','--wait','--pipe','--quiet','--property=User=bo','--property=Group=bo','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=RuntimeMaxSec=15s',SFCTL,'--json','private',op,target,'--brake-key-file',key,check=False,timeout=20)

def frontend_negative(role,target,duplicate=False):
 # The real key is read only inside the bo process for duplicate-header denial.
 # The worker receives only a fixed synthetic key; it must not read either real file.
 code=r"""import os,socket,sys
role,target,duplicate=sys.argv[1:]
if role=='bo':
 fd=os.open('/etc/software-factory-goose/operator-brake.key',os.O_RDONLY|os.O_NOFOLLOW);st=os.fstat(fd)
 if st.st_uid!=1000 or st.st_mode&0o7777!=0o600 or st.st_nlink!=1:raise RuntimeError('bad key metadata')
 key=os.read(fd,33);os.close(fd)
 if len(key)!=32:raise RuntimeError('bad key length')
else:
 for p in ('/etc/software-factory-goose/operator-brake.key','/etc/software-factory-goose/brake.key'):
  try: fd=os.open(p,os.O_RDONLY);os.close(fd);raise RuntimeError('forbidden credential access')
  except PermissionError: pass
 key=bytes([9])*32
body=('{\"target\":\"'+target+'\"}').encode();header=key.hex();s=socket.socket(socket.AF_UNIX);s.settimeout(5);s.connect('/run/software-factory-goose/brake.sock')
request=('POST /status HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\nx-brake-key: '+header+'\r\n'+(('x-brake-key: '+header+'\r\n') if duplicate=='yes' else '')+'Connection: close\r\n\r\n').encode()+body
s.sendall(request);response=b''
while len(response)<256 and b'\r\n' not in response:
 chunk=s.recv(256)
 if not chunk:break
 response+=chunk
print(response.split(b'\r\n',1)[0].decode())
"""
 if role not in ('bo','sfgoose-worker'):raise RuntimeError('invalid test role')
 unit='sfactory-brake-peer-'+new_id().lower()+'.service'
 if system('show',unit,'-p','LoadState','--value',check=False).stdout.strip() not in ('','not-found'):raise RuntimeError('peer unit collision')
 # The temporary worker process receives bo group only to reach the socket;
 # no account/group membership is changed and 0600 human key must stay unreadable.
 return run('/usr/bin/systemd-run','--unit='+unit,'--collect','--wait','--pipe','--quiet','--property=User='+role,'--property=Group=bo','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=RuntimeMaxSec=15s','/usr/bin/python3','-I','-B','-c',code,role,target,'yes' if duplicate else 'no',check=False,timeout=20)

def main():
 if sys.argv!=[sys.argv[0],'--run'] or os.geteuid()!=0:raise RuntimeError('root and explicit canary required')
 metadata(ROOT,0o700);metadata(STATE,0o700)
 if pwd.getpwnam('sfgoose-brake').pw_uid!=2003 or grp.getgrnam('sfgoose-brake').gr_gid!=2003:raise RuntimeError('brake identity mismatch')
 binary=pathlib.Path('/usr/local/libexec/software-factory-goose/sfactory_root_stop');s=binary.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or s.st_mode&0o022 or hashlib.sha256(binary.read_bytes()).hexdigest()!=EXPECTED:raise RuntimeError('installed binary mismatch')
 if system('is-active','--quiet',SOCKUNIT,check=False).returncode==0 or system('is-active','--quiet',SERVICE,check=False).returncode==0 or pathlib.Path(SOCKET).exists():raise RuntimeError('stop endpoint already active')
 if system('is-active','--quiet',BRAKEUNIT,check=False).returncode==0 or system('is-active','--quiet',BRAKESERVICE,check=False).returncode==0 or pathlib.Path('/run/software-factory-goose/brake.sock').exists():raise RuntimeError('brake endpoint already active')
 checked_binary(SFCTL,SFCTL_EXPECTED);checked_binary('/usr/local/libexec/software-factory-goose/sfactory_brake_frontend',FRONT_EXPECTED)
 guard();shared_before=shared_snapshot();mask_sha=install_mask();checked_brake_units()
 target=new_id();task=new_id();name='sfactory'+target.lower()+'.slice';unit='sfactory'+target.lower()+'-anchor.service';cg=pathlib.Path('/sys/fs/cgroup')/name
 if cg.exists() or (ROOT/(target+'.json')).exists() or system('show',unit,'-p','LoadState','--value',check=False).stdout.strip() not in ('','not-found'):raise RuntimeError('canary identity collision')
 dummy=pathlib.Path('/etc/software-factory-goose')/('brake-canary-'+target+'.key')
 if dummy.exists() or dummy.is_symlink():raise RuntimeError('dummy key collision')
 store(STATE/(target+'.canary-intent.json'),{'target_id':target,'task_id':task,'slice':name,'unit':unit,'dummy_key':str(dummy),'operation':'operator-frontend-sleeper-stop'})
 fd=os.open(dummy,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:
  os.fchmod(f.fileno(),0o600);os.fchown(f.fileno(),1000,1000);f.write(bytes([9])*32);f.flush();os.fsync(f.fileno());dummy_identity=(os.fstat(f.fileno()).st_dev,os.fstat(f.fileno()).st_ino)
 fd=os.open(dummy.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 print('CANARY_TARGET '+target,flush=True)
 # The unit is new and unique; this code only launches harmless owned sleepers.
 worker="import os,subprocess,time\nfor label,path in [('MIGRATION','/sys/fs/cgroup/cgroup.procs'),('TASK_MIGRATION','/sys/fs/cgroup/"+name+"/cgroup.procs'),('FREEZE','/sys/fs/cgroup/"+name+"/cgroup.freeze')]:\n try:\n  fd=os.open(path,os.O_WRONLY);os.close(fd);print(label+'_WRITE_ALLOWED',flush=True)\n except OSError:print(label+'_WRITE_DENIED',flush=True)\nsubprocess.Popen(['/usr/bin/setsid','/usr/bin/sleep','120']);time.sleep(120)"
 # A returned systemd-run success establishes ownership; a timeout does not.
 run('/usr/bin/systemd-run','--unit='+unit,'--slice='+name,'--property=Description='+unit,'--property=User=sfgoose-worker','--property=PrivateNetwork=yes','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=RuntimeMaxSec=120s','/usr/bin/python3','-I','-B','-c',worker)
 try:
  wait(cg.exists);procs=cg/unit/'cgroup.procs';wait(procs.exists);wait(lambda:len(procs.read_text().splitlines())>=2)
  def denial_logs():return run('/usr/bin/journalctl','--unit',unit,'--no-pager','--output=cat').stdout
  wait(lambda:'FREEZE_WRITE_' in denial_logs())
  logs=denial_logs()
  if any(x not in logs for x in ('MIGRATION_WRITE_DENIED','TASK_MIGRATION_WRITE_DENIED','FREEZE_WRITE_DENIED')) or 'WRITE_ALLOWED' in logs:raise RuntimeError('worker cgroup access boundary unverified')
  st=cg.stat();boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  store(ROOT/(target+'.json'),{'schema':1,'target_id':target,'task_id':task,'generation':target,'boot_id':boot,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino})
 except Exception:
  # No brake request or Docker RPC was issued. Clean only the verified unit;
  # retain all intent/catalogue records and never guess about foreign children.
  try:
   desc=system('show',unit,'-p','Description','--value').stdout.strip();group=system('show',unit,'-p','ControlGroup','--value').stdout.strip()
   if desc!=unit or group not in ('','/'+name+'/'+unit) or (cg.exists() and any(p.name!=unit for p in cg.iterdir() if p.is_dir())):raise RuntimeError('pre-admission scope unresolved')
   system('stop',unit)
   if cg.exists() and dict(line.split() for line in (cg/'cgroup.events').read_text().splitlines()).get('populated')!='0':raise RuntimeError('pre-admission scope still populated')
   system('stop',name)
  except Exception:print('RETAINED_PRE_ADMISSION target='+target+' slice='+name+' unit='+unit,flush=True)
  raise
 try:
  system('start',SOCKUNIT)
  system('start',BRAKEUNIT)
  bad=peer('sfgoose-control',{'operation':'stop','target':target})
  pre=system('show',SERVICE,'-p','ExecStartPre','--value').stdout
  if not preflight_succeeded(pre):raise RuntimeError('in-context Docker mask preflight unverified')
  if bad.returncode==0 and bad.stdout.strip():raise RuntimeError('wrong UID reached authority')
  if (STATE/(target+'.closed')).exists():raise RuntimeError('wrong UID caused closure')
  unknown=peer('sfgoose-brake',{'operation':'status','target':new_id()})
  if unknown.returncode or json.loads(unknown.stdout).get('outcome')!='unavailable':raise RuntimeError('unknown target not denied')
  wrong=bo_cli(target,'status',str(dummy))
  if wrong.returncode==0 or (STATE/(target+'.closed')).exists():raise RuntimeError('ordinary synthetic bearer accepted')
  wrong_peer=frontend_negative('sfgoose-worker',target)
  if wrong_peer.returncode or ' 403 ' not in wrong_peer.stdout or (STATE/(target+'.closed')).exists():raise RuntimeError('wrong peer or key isolation not denied')
  duplicate=frontend_negative('bo',target,True)
  if duplicate.returncode or ' 403 ' not in duplicate.stdout or (STATE/(target+'.closed')).exists():raise RuntimeError('duplicate credential accepted')
  positive=bo_cli(target,'stop',HUMAN_KEY)
  if positive.returncode==0 or json.loads(positive.stdout)!='pending':raise RuntimeError('operator stop was not accepted as pending')
  events=dict(line.split() for line in (cg/'cgroup.events').read_text().splitlines())
  if cg.stat().st_ino!=st.st_ino or events.get('frozen')!='1' or events.get('populated')!='0':raise RuntimeError('kernel observation missing')
  cli_status=bo_cli(target,'status',HUMAN_KEY)
  if cli_status.returncode:raise RuntimeError('operator status unavailable')
  cli_observation=json.loads(cli_status.stdout)
  if cli_observation.get('target_id')!=target or not cli_observation.get('frozen') or not cli_observation.get('empty') or cli_observation.get('engine_reconciled') is not False:raise RuntimeError('operator status binding mismatch')
  status=peer('sfgoose-brake',{'operation':'status','target':target});o=json.loads(status.stdout).get('observation') or {}
  if status.returncode or not o.get('observed') or o.get('target_id')!=target or o.get('boot_id')!=boot or o.get('cgroup_ino')!=st.st_ino or o.get('engine_reconciled') is not False:raise RuntimeError('protected status unavailable')
  desc=system('show',unit,'-p','Description','--value').stdout.strip();group=system('show',unit,'-p','ControlGroup','--value').stdout.strip()
  if desc!=unit or group not in ('','/'+name+'/'+unit):raise RuntimeError('anchor identity mismatch')
  if any(p.name!=unit for p in cg.iterdir() if p.is_dir()):raise RuntimeError('foreign cgroup child')
  # No pending Docker operation exists in this native sleeper fixture.
  system('stop',unit);system('stop',name)
  if cg.exists():raise RuntimeError('owned slice remains')
  system('stop',BRAKEUNIT);system('stop',BRAKESERVICE)
  if pathlib.Path('/run/software-factory-goose/brake.sock').exists() or system('is-active','--quiet',BRAKEUNIT,check=False).returncode==0 or system('is-active','--quiet',BRAKESERVICE,check=False).returncode==0:raise RuntimeError('brake endpoint cleanup unresolved')
  system('stop',SOCKUNIT);system('stop',SERVICE)
  if pathlib.Path(SOCKET).exists() or system('is-active','--quiet',SOCKUNIT,check=False).returncode==0 or system('is-active','--quiet',SERVICE,check=False).returncode==0:raise RuntimeError('owned endpoint cleanup unresolved')
  current=dummy.lstat()
  if (current.st_dev,current.st_ino)!=(dummy_identity[0],dummy_identity[1]) or current.st_uid!=1000 or current.st_nlink!=1 or stat.S_IMODE(current.st_mode)!=0o600:raise RuntimeError('dummy key identity changed')
  dummy.unlink();fd=os.open(dummy.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
  guard()
  if shared_snapshot()!=shared_before:raise RuntimeError('shared service or container snapshot changed')
  store(STATE/(target+'.canary-receipt.json'),{'target_id':target,'slice':name,'unit':unit,'operator_frontend_verified':True,'kernel_stop_verified':True,'engine_reconciled':False,'slice_removed':True,'docker_mask_sha256':mask_sha})
  print('PASS actual bo CLI to brake frontend and root cgroup stop; exact owned slice removed; engine reconciliation remains false',flush=True)
  print('RETAINED_CATALOG '+str(ROOT/(target+'.json'))+' CLOSED '+str(STATE/(target+'.closed')),flush=True)
 except Exception:
  print('RETAINED_UNKNOWN target='+target+' slice='+name+' unit='+unit,flush=True);raise
if __name__=='__main__':main()
