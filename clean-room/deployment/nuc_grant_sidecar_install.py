#!/usr/bin/env python3
"""One-shot, root-reviewed additive grant-canary sidecar; no launcher effects.

Keeps old SDK/URI and journal state. A registration timeout is unknown and must
never be retried automatically. This is not a production admission mechanism.
"""
import errno,hashlib,json,os,pathlib,pwd,re,stat,subprocess,sys
ETC=pathlib.Path('/etc/software-factory-goose');RUN=pathlib.Path('/run/software-factory-goose');UNIT=pathlib.Path('/etc/systemd/system');PREFIX=pathlib.Path('/usr/local/libexec/software-factory-goose')
OLD='software-factory-goose-private-';NAME='software-factory-goose-grant-canary-'
SOURCE=pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX/stripped/private-grant-sidecar3')
SOURCE_SHA='9b1138c07c12a5e0b5d9e7de5675d6ebc7fb425b5cec0874f8ce7985a1d9779b'
INTENT=ETC/'grant-sidecar-started.json';DONE=ETC/'grant-sidecar-complete.json'
GEN='01M65GTQYKNHFXSJSZ55D7T362';TASK='01M65GTQYKQQMN3NG1V0EFCVH5';INTAKE='01M65GTQYKXECJWHCPKQD248SY'
QUEUE='root-grant-canary-20261030';WORKER='root-grant-canary-worker'
CATALOG_SHA='4218228a2a9c0fcc51ec838414ebd92542b18e06ddd40d7a1a2b628d4d8caf19'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LANG':'C'}
REGISTER=b'#!/usr/bin/python3\n"""Single non-force registration of one fixed, new private SDK URI."""\nimport http.client,json,os,re,socket,time\nif os.geteuid()!=2000:raise RuntimeError(\'registration identity mismatch\')\nfor port in (9082,9070):\n for _ in range(150):\n  try:\n   with socket.create_connection((\'127.0.0.1\',port),timeout=.1):break\n  except OSError:time.sleep(.1)\n else:raise RuntimeError(\'private service unavailable\')\nbody=json.dumps({\'uri\':\'http://127.0.0.1:9082\',\'force\':False},separators=(\',\',\':\')).encode()\nc=http.client.HTTPConnection(\'127.0.0.1\',9070,timeout=10)\ntry:\n c.request(\'POST\',\'/deployments\',body,{\'Content-Type\':\'application/json\'})\n r=c.getresponse();raw=r.read(65537)\n if r.status!=201 or len(raw)>65536:raise RuntimeError(\'registration rejected or unknown\')\n data=json.loads(raw);ident=data.get(\'id\');services=data.get(\'services\')\n if not isinstance(ident,str) or not re.fullmatch(r\'[A-Za-z0-9_-]{1,128}\',ident) or not isinstance(services,list) or len(services)!=4:raise RuntimeError(\'registration response invalid or unknown\')\n print(\'GRANT_REGISTRATION \'+json.dumps({\'id\':ident,\'service_count\':len(services)},sort_keys=True),flush=True)\nfinally:c.close()\n'
REGISTER_SHA='0438b1f629e94ca460aaa95e87bac176d3b8a490e1ae1f78bbe9913223d27bd1'
SNAPSHOT_SOURCE=b'#!/usr/bin/env python3\n"""One-shot exact private-runtime restart for the retained canary; no other service restart."""\nimport errno,hashlib,json,os,pathlib,stat,subprocess,sys\nETC=pathlib.Path(\'/etc/software-factory-goose\');RUN=pathlib.Path(\'/run/software-factory-goose\')\nUNIT=pathlib.Path(\'/etc/systemd/system\');PREFIX=\'software-factory-goose-private-\'\nINTENT=ETC/\'private-runtime-restart-started.json\';DONE=ETC/\'private-runtime-restart-complete.json\'\nENV={\'PATH\':\'/usr/sbin:/usr/bin:/sbin:/bin\',\'HOME\':\'/nonexistent\',\'LANG\':\'C\'}\nEXPECTED={\n \'/etc/software-factory-goose/runtime.json\':(\'53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6\',0o644),\n \'/etc/software-factory-goose/private-genesis.json\':(\'395151c9c7ef720740288fc23234117e6473667baf71997e949d3db4f61cea75\',0o644),\n \'/etc/software-factory-goose/private-bootstrap-complete\':(\'905c9966bb6cbdf8a8441beed4a2c6c8f51a5f1b32e32856ff963b440478beb1\',0o644),\n \'/usr/local/libexec/software-factory-goose/private-runtime\':(\'9ca260b3aebcfcd082ac6521825b20a4312b2ec991ab03a957ea89ffa6288082\',0o755),\n \'/etc/systemd/system/software-factory-goose-private-runtime.service\':(\'5fe9af9180d08242e40614a5b1994ea3b4933bc92694b28abf8d48fcc69e3ebe\',0o644),\n}\nSOCKETS={\'intake.sock\':(25,2600598,1000),\'worker.sock\':(25,2600602,2001)}\nSUPPORT={\'host-net.service\':(418527,64*1024**2,16,50),\'net.service\':(418529,64*1024**2,16,50),\'postgres.service\':(418536,1024**3,128,200),\'restate.service\':(418551,4*1024**3,256,200)}\nTARGET=\'runtime.service\';TARGET_PID=418558\n\ndef require(x,message):\n if not x:raise RuntimeError(message)\ndef noacl(path,directory=False,follow=False):\n for attr in ((\'system.posix_acl_access\',\'system.posix_acl_default\') if directory else (\'system.posix_acl_access\',)):\n  try:os.getxattr(path,attr,follow_symlinks=follow)\n  except OSError as e:require(e.errno==errno.ENODATA,\'ACL unavailable\')\n  else:raise RuntimeError(\'ACL forbidden\')\ndef check_ancestor(path,mode):\n s=os.lstat(path);require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode,\'unsafe root ancestor\');noacl(path,True)\ndef file_info(path,digest,mode):\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)\n try:\n  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode and s.st_size<=100_000_000,\'file identity mismatch\')\n  try:os.getxattr(fd,\'system.posix_acl_access\')\n  except OSError as e:require(e.errno==errno.ENODATA,\'file ACL unavailable\')\n  else:raise RuntimeError(\'file ACL forbidden\')\n  h=hashlib.sha256();data=bytearray() if s.st_size<=4096 else None;total=0\n  while True:\n   b=os.read(fd,65536)\n   if not b:break\n   total+=len(b);require(total<=s.st_size,\'file grew\');h.update(b)\n   if data is not None:data.extend(b)\n  require(total==s.st_size and h.hexdigest()==digest,\'file digest mismatch\')\n  return {\'dev\':s.st_dev,\'ino\':s.st_ino,\'sha256\':digest},bytes(data) if data is not None else None\n finally:os.close(fd)\ndef command(args,timeout=15):\n p=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)\n require(p.returncode==0 and len(p.stdout)<=16384 and len(p.stderr)<=16384,\'systemd outcome unavailable\')\n return p.stdout.decode().strip()\ndef service(name,memory,pids,cpu):\n full=PREFIX+name;output=command([\'/usr/bin/systemctl\',\'show\',full,\'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,ControlGroup\',\'--no-pager\'])\n values=dict(line.split(\'=\',1) for line in output.splitlines())\n require(values.get(\'LoadState\')==\'loaded\' and values.get(\'ActiveState\')==\'active\' and values.get(\'Names\')==full and values.get(\'FragmentPath\')==str(UNIT/full) and values.get(\'DropInPaths\')==str(UNIT/(full+\'.d\')/\'50-resources.conf\'),\'loaded service mismatch\')\n pid=int(values[\'MainPID\']);require(pid>1,\'service PID missing\');group=\'/system.slice/\'+full;require(values.get(\'ControlGroup\')==group,\'service cgroup mismatch\')\n path=pathlib.Path(\'/sys/fs/cgroup\'+group);s=os.stat(path);require(s.st_uid==0,\'cgroup owner mismatch\');ident=(s.st_dev,s.st_ino)\n quota=(path/\'cpu.max\').read_text().split();require((path/\'memory.max\').read_text().strip()==str(memory) and (path/\'pids.max\').read_text().strip()==str(pids) and len(quota)==2 and all(x.isdigit() for x in quota) and int(quota[0])*100==int(quota[1])*cpu,\'live cgroup resource mismatch\')\n s=os.stat(path);require((s.st_dev,s.st_ino)==ident,\'cgroup changed\')\n return {\'pid\':pid,\'cgroup_dev\':s.st_dev,\'cgroup_ino\':s.st_ino}\ndef snapshot(expected_pid=None):\n require(os.geteuid()==0,\'root required\')\n for p,mode in [(\'/\',0o755),(\'/etc\',0o755),(\'/etc/software-factory-goose\',0o711),(\'/etc/systemd\',0o755),(\'/etc/systemd/system\',0o755),(\'/run\',0o755),(\'/run/software-factory-goose\',0o755),(\'/usr\',0o755),(\'/usr/local\',0o755),(\'/usr/local/libexec\',0o755),(\'/usr/local/libexec/software-factory-goose\',0o755)]:check_ancestor(p,mode)\n files={};contents={}\n for path,(digest,mode) in EXPECTED.items():files[path],contents[path]=file_info(path,digest,mode)\n cfg=json.loads(contents[str(ETC/\'runtime.json\')]);genesis=json.loads(contents[str(ETC/\'private-genesis.json\')])\n boot=pathlib.Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip();require(cfg[\'boot_id\']==boot and genesis[\'boot_id\']==boot and genesis[\'postgres_system_id\']==\'7702303394074795435\' and (genesis[\'pgdata_dev\'],genesis[\'pgdata_ino\'])==(66306,19138550),\'bootstrap/boot identity mismatch\')\n sockets={}\n for name,(dev,ino,gid) in SOCKETS.items():\n  path=RUN/name;s=os.lstat(path);require(stat.S_ISSOCK(s.st_mode) and (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(dev,ino,0,gid,0o660),\'socket mismatch\');noacl(path)\n  sockets[name]={\'dev\':dev,\'ino\':ino,\'gid\':gid}\n support={}\n for name,(pid,memory,pids,cpu) in SUPPORT.items():\n  value=service(name,memory,pids,cpu);require(value[\'pid\']==pid,\'support PID changed\');support[name]=value\n target=service(TARGET,512*1024**2,128,100)\n if expected_pid is not None:require(target[\'pid\']==expected_pid,\'runtime PID mismatch\')\n return {\'boot_id\':boot,\'files\':files,\'sockets\':sockets,\'support\':support,\'runtime\':target,\'pg_system_id\':\'7702303394074795435\'}\ndef store(path,value):\n data=json.dumps(value,sort_keys=True,separators=(\',\',\':\')).encode()+b\'\\n\';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)\n try:\n  os.fchmod(fd,0o600);view=memoryview(data)\n  while view:\n   n=os.write(fd,view);require(n>0,\'short receipt\');view=view[n:]\n  os.fsync(fd)\n finally:os.close(fd)\n fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n try:os.fsync(fd)\n finally:os.close(fd)\ndef plan():\n require(not os.path.lexists(INTENT) and not os.path.lexists(DONE),\'restart already attempted\')\n return {\'format\':1,\'before\':snapshot(TARGET_PID),\'scope\':\'exact private runtime only; no registration or shared service restart\'}\ndef apply(approved):\n require(plan()==approved,\'reviewed restart plan changed\')\n store(INTENT,approved)\n # Timeout or failed response is unknown; retain intent and never retry here.\n command([\'/usr/bin/systemctl\',\'restart\',PREFIX+TARGET],timeout=45)\n after=snapshot()\n require(after[\'runtime\'][\'pid\']!=approved[\'before\'][\'runtime\'][\'pid\'],\'runtime PID did not change\')\n for key in (\'boot_id\',\'files\',\'sockets\',\'support\',\'pg_system_id\'):require(after[key]==approved[\'before\'][key],\'post-restart binding changed\')\n store(DONE,{\'format\':1,\'before\':approved[\'before\'][\'runtime\'],\'after\':after[\'runtime\']})\n print(json.dumps({\'private_runtime_restarted\':True,\'old_pid\':approved[\'before\'][\'runtime\'][\'pid\'],\'new_pid\':after[\'runtime\'][\'pid\']},sort_keys=True))\nif __name__==\'__main__\':\n if sys.argv==[sys.argv[0],\'--plan\']:print(json.dumps(plan(),sort_keys=True,indent=2))\n elif sys.argv==[sys.argv[0],\'--apply\']:\n  raw=sys.stdin.buffer.read(1_000_001);require(len(raw)<=1_000_000,\'plan too large\');apply(json.loads(raw))\n else:raise SystemExit(\'expected --plan or --apply\')\n'
SNAPSHOT_SHA='1c2c6225b6c13b202f888cc3589b69c94ecb265959e891e68bc555d5eb20d20f'
OWNED=False

def require(x,msg):
 if not x:raise RuntimeError(msg)
def noacl(fd,directory=False):
 for attr in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(fd,attr)
  except OSError as e:require(e.errno==errno.ENODATA,'ACL unavailable')
  else:raise RuntimeError('ACL forbidden')
def directory(path,uid,gid,mode):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require((s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(uid,gid,mode),'directory mismatch');noacl(fd,True)
 finally:os.close(fd)
def read(path,mode,digest=None,maxsize=65536):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode and s.st_size<=maxsize,'file mismatch');noacl(fd)
  data=bytearray()
  while len(data)<=maxsize:
   b=os.read(fd,min(65536,maxsize+1-len(data)))
   if not b:break
   data.extend(b)
  actual=hashlib.sha256(data).hexdigest();require(len(data)==s.st_size and (digest is None or actual==digest),'file digest mismatch')
  return bytes(data)
 finally:os.close(fd)
def binary(dest=None):
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);out=None
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_nlink==1 and s.st_size<=100_000_000,'binary source mismatch')
  if dest is not None:out=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o755)
  h=hashlib.sha256();total=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   total+=len(b);require(total<=s.st_size,'binary grew');h.update(b)
   if out is not None:
    view=memoryview(b)
    while view:
     n=os.write(out,view);require(n>0,'short binary copy');view=view[n:]
  require(total==s.st_size and h.hexdigest()==SOURCE_SHA,'binary digest mismatch')
  if out is not None:os.fchmod(out,0o755);os.fsync(out)
  return {'dev':s.st_dev,'ino':s.st_ino,'size':s.st_size,'sha256':SOURCE_SHA}
 finally:
  if out is not None:os.close(out)
  os.close(fd)
def syncdir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def store(path,data,mode=0o644):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 try:
  os.fchmod(fd,mode);view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 syncdir(path.parent)
def ctl(*args):
 p=subprocess.run(['/usr/bin/systemctl',*args],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
 require(p.returncode==0 and len(p.stdout)<=16384 and len(p.stderr)<=16384,'systemd outcome unavailable')
 return p.stdout.decode().strip()
def units():
 net=OLD+'net.service';common=f'BindsTo={net}\nAfter={net}\nJoinsNamespaceOf={net}\n'
 svc='PrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nRestart=no\nMemoryMax=512M\nTasksMax=128\nCPUQuota=100%\n'
 result={}
 for suffix,path,gid,mode,fdname in [('intake.socket','grant-intake.sock','1000','0660','intake'),('worker.socket','grant-worker.sock','2001','0660','worker'),('launch.socket','launch-grant.sock','0','0600','launch-grant')]:
  result[NAME+suffix]=f'[Unit]\nBindsTo={net}\nAfter={net}\n[Socket]\nListenStream={RUN}/{path}\nSocketUser=root\nSocketGroup={gid}\nSocketMode={mode}\nFileDescriptorName={fdname}\nService={NAME}runtime.service\n'.encode()
 result[NAME+'runtime.service']=f'[Unit]\n{common}Requires={OLD}postgres.service {OLD}restate.service\nAfter={OLD}postgres.service {OLD}restate.service\n[Service]\nType=simple\nUser=sfgoose-control\n{svc}Sockets={NAME}intake.socket {NAME}worker.socket {NAME}launch.socket\nExecStart={PREFIX}/private-grant-sidecar\n'.encode()
 result[NAME+'register.service']=f'[Unit]\n{common}Requires={NAME}runtime.service {OLD}restate.service\nAfter={NAME}runtime.service {OLD}restate.service\n[Service]\nType=oneshot\nUser=sfgoose-control\n{svc}ExecStart=/usr/bin/python3 -I -B {PREFIX}/private-grant-register.py\n'.encode()
 return result

def old_snapshot():
 require(hashlib.sha256(SNAPSHOT_SOURCE).hexdigest()==SNAPSHOT_SHA,'snapshot helper mismatch')
 scope={'__name__':'private_snapshot'};exec(compile(SNAPSHOT_SOURCE,'<pinned-snapshot>','exec'),scope)
 return scope['snapshot'](424877)

def preflight():
 require(os.geteuid()==0,'root required')
 for path,uid,gid,mode in [(ETC,0,0,0o711),(RUN,0,0,0o755),(UNIT,0,0,0o755),(PREFIX,0,0,0o755),(pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX'),1000,1000,0o700),(SOURCE.parent,1000,1000,0o700)]:directory(path,uid,gid,mode)
 require(pwd.getpwnam('sfgoose-control').pw_uid==2000,'control identity mismatch')
 destinations=[INTENT,DONE,ETC/'grant-runtime.json',ETC/'grant-evidence.json',ETC/'grant-bootstrap-complete',PREFIX/'private-grant-sidecar',PREFIX/'private-grant-register.py',RUN/'grant-intake.sock',RUN/'grant-worker.sock',RUN/'launch-grant.sock']+[UNIT/n for n in units()]
 require(not any(os.path.lexists(p) for p in destinations),'sidecar destination occupied')
 # All names and inherited drop-ins must be absent before creating any unit.
 p=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
 paths=[pathlib.Path(x) for x in p.stdout.decode().splitlines()];require(paths,'unit paths unavailable')
 for name in units():
  require(ctl('show',name,'--property=LoadState','--value')=='not-found','unit name occupied')
  stem,kind=name.rsplit('.',1);candidates=[name,name+'.d',kind+'.d']+[stem[:i+1]+'.'+kind+'.d' for i,c in enumerate(stem) if c=='-']
  for parent in paths:
   for candidate in candidates:require(not os.path.lexists(parent/candidate),'unit alias or drop-in collision')
 old=old_snapshot();source=binary()
 cfg=json.loads(read(ETC/'runtime.json',0o644,'53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6'))
 evidence=read(ETC/'evidence.json',0o644,'b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a')
 require(cfg['evidence_sha256']==hashlib.sha256(evidence).hexdigest(),'original catalog mismatch')
 require(hashlib.sha256(REGISTER).hexdigest()==REGISTER_SHA,'registration source mismatch')
 return {'format':1,'old_snapshot':old,'binary':source,'units':{name:hashlib.sha256(data).hexdigest() for name,data in units().items()},'register_sha256':REGISTER_SHA,'task':TASK,'intent':INTAKE,'generation':GEN,'queue':QUEUE,'worker':WORKER,'catalog_sha256':CATALOG_SHA,'sdk_uri':'http://127.0.0.1:9082','scope':'no engine effects; one existing private journal'}

def verify_new_units():
 for name in units():
  output=ctl('show',name,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec','--no-pager')
  props={}
  for line in output.splitlines():
   key,sep,value=line.partition('=');require(sep and key not in props,'loaded unit parse error');props[key]=value
  require(props.get('LoadState')=='loaded' and props.get('ActiveState')=='inactive' and props.get('Names')==name and props.get('FragmentPath')==str(UNIT/name) and props.get('DropInPaths','')=='','new unit loaded identity mismatch')
  if name.endswith('.service'):
   require(props.get('MainPID')=='0' and props.get('MemoryMax')==str(512*1024**2) and props.get('TasksMax')=='128' and props.get('CPUQuotaPerSecUSec') in ('1s','1000000us'),'new unit resource mismatch')


def sidecar_running():
 name=NAME+'runtime.service'
 output=ctl('show',name,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,ControlGroup','--no-pager')
 props=dict(line.split('=',1) for line in output.splitlines())
 require(props.get('LoadState')=='loaded' and props.get('ActiveState')=='active' and props.get('Names')==name and props.get('FragmentPath')==str(UNIT/name) and props.get('DropInPaths','')=='' and int(props.get('MainPID','0'))>1,'sidecar service identity mismatch')
 group='/system.slice/'+name;require(props.get('ControlGroup')==group,'sidecar cgroup mismatch')
 path=pathlib.Path('/sys/fs/cgroup'+group);st=os.stat(path);require(st.st_uid==0,'sidecar cgroup owner mismatch')
 before=(st.st_dev,st.st_ino);quota=(path/'cpu.max').read_text().split()
 require((path/'memory.max').read_text().strip()==str(512*1024**2) and (path/'pids.max').read_text().strip()=='128' and len(quota)==2 and all(x.isdigit() for x in quota) and int(quota[0])==int(quota[1]),'sidecar kernel resource mismatch')
 st=os.stat(path);require((st.st_dev,st.st_ino)==before,'sidecar cgroup changed')
 sockets={}
 for filename,gid,mode in [('grant-intake.sock',1000,0o660),('grant-worker.sock',2001,0o660),('launch-grant.sock',0,0o600)]:
  p=RUN/filename;info=os.lstat(p)
  require(stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and info.st_gid==gid and stat.S_IMODE(info.st_mode)==mode,'sidecar socket mismatch')
  try:os.getxattr(p,'system.posix_acl_access',follow_symlinks=False)
  except OSError as e:require(e.errno==errno.ENODATA,'socket ACL unavailable')
  else:raise RuntimeError('socket ACL forbidden')
  sockets[filename]={'dev':info.st_dev,'ino':info.st_ino,'gid':gid,'mode':mode}
 return {'pid':int(props['MainPID']),'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'sockets':sockets}


def registration_receipt():
 invocation=ctl('show',NAME+'register.service','--property=InvocationID','--value')
 require(re.fullmatch(r'[0-9a-f]{32}',invocation) is not None,'registration invocation identity unavailable')
 p=subprocess.run(['/usr/bin/journalctl','_SYSTEMD_INVOCATION_ID='+invocation,'--no-pager','-o','cat'],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
 require(len(p.stdout)<=65536 and len(p.stderr)<=8192,'registration log too large')
 lines=[x.removeprefix('GRANT_REGISTRATION ') for x in p.stdout.decode().splitlines() if x.startswith('GRANT_REGISTRATION ')]
 require(len(lines)==1,'registration result unknown');obj=json.loads(lines[0])
 require(set(obj)=={'id','service_count'} and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',obj['id']) and obj['service_count']==4,'registration result mismatch')
 return {'invocation_id':invocation,'deployment_id':obj['id'],'service_count':4}

def apply(approved):
 global OWNED
 require(preflight()==approved,'reviewed plan changed')
 store(INTENT,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);OWNED=True
 cfg=json.loads(read(ETC/'runtime.json',0o644,'53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6'))
 evidence=read(ETC/'evidence.json',0o644,'b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a')
 cfg.update(sdk_port=9082,intent_id=INTAKE,task_id=TASK,queue_id=QUEUE,worker_id=WORKER)
 cfg['launch_scope']={'task_id':TASK,'intent_id':INTAKE,'queue_id':QUEUE,'generation':GEN,'spec':{'repository':cfg['request']['repository'],'base_revision':cfg['request']['base_revision']},'worker_id':WORKER,'catalog_sha256':CATALOG_SHA}
 store(ETC/'grant-evidence.json',evidence);store(ETC/'grant-runtime.json',json.dumps(cfg,sort_keys=True,separators=(',',':')).encode()+b'\n')
 binary(PREFIX/'private-grant-sidecar');syncdir(PREFIX);store(PREFIX/'private-grant-register.py',REGISTER,0o755)
 for name,data in units().items():store(UNIT/name,data)
 ctl('daemon-reload');verify_new_units()
 for suffix in ('intake.socket','worker.socket','launch.socket','runtime.service'):ctl('start',NAME+suffix)
 before=sidecar_running()
 # This one-shot POST may commit before its reply; no automatic retry or rollback.
 ctl('start',NAME+'register.service');receipt=registration_receipt()
 require(old_snapshot()==approved['old_snapshot'],'old service identity changed')
 require(sidecar_running()==before,'sidecar identity changed during registration')
 receipt['sidecar']=before
 store(DONE,json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 store(ETC/'grant-bootstrap-complete',b'private canary bootstrap completed; acceptance tests required\n',0o644)
 print(json.dumps({'sidecar_registered':True,'deployment_id':receipt['deployment_id'],'production_accepted':False,'launch_enabled':False},sort_keys=True))

if __name__=='__main__':
 try:
  if sys.argv==[sys.argv[0],'--plan']:print(json.dumps(preflight(),sort_keys=True,indent=2))
  elif sys.argv==[sys.argv[0],'--apply']:
   raw=sys.stdin.buffer.read(1_000_001);require(len(raw)<=1_000_000,'plan too large');apply(json.loads(raw))
  else:raise RuntimeError('expected --plan or --apply')
 except Exception:
  if OWNED:
   for suffix in ('intake.socket','worker.socket','launch.socket','runtime.service','register.service'):
    try:ctl('stop',NAME+suffix)
    except Exception:print('owned sidecar stop outcome unresolved',file=sys.stderr)
  raise
