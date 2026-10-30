#!/usr/bin/env python3
"""Fixed reviewed identity PLAN/APPLY through an owned NUC administrative bridge.

No generic command/code argument. Source is the adjacent installer, pinned by digest.
Exact failed/unknown bridge identity is retained. This is a deployment tool, never a
worker or production ingress. No credentials are accepted or printed.
"""
import hashlib,json,pathlib,subprocess,sys

REMOTE=r'''import base64,hashlib,json,os,pathlib,subprocess,sys,tempfile,uuid,zlib
SOURCE=__SOURCE__;OP=__OP__;PLAN=__PLAN__
IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
ROOT=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-identity-admin-'));ROOT.chmod(0o700)
TOKEN=uuid.uuid4().hex;NAME='sfactory-identity-admin-'+TOKEN;LABEL='org.software-factory.identity-admin'
D=['/usr/bin/docker','--host','unix:///run/docker.sock'];ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'}
def cmd(*args,check=True,timeout=20):return subprocess.run(list(args),check=check,capture_output=True,text=True,timeout=timeout,env=ENV)
def save(name,value):
 fd=os.open(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def inspect(target):
 r=cmd(*D,'inspect',target,check=False)
 if r.returncode:
  if 'no such object' in r.stderr.lower():return None
  raise RuntimeError('bridge inspection unavailable')
 objects=json.loads(r.stdout)
 if len(objects)!=1:raise RuntimeError('ambiguous bridge')
 o=objects[0];h=o['HostConfig'];m=o['Mounts']
 caps={x.removeprefix('CAP_') for x in h['CapAdd'] or []}
 if o['Config']['Entrypoint']!=['python3'] or o['Config']['Cmd']!=['-I','-B','-c',boot] or h['Memory']!=192*1024*1024 or h['PidsLimit']!=32 or h['NanoCpus']!=500000000 or h['RestartPolicy']['Name']!='no' or o['Name']!='/'+NAME or (o['Config']['Labels'] or {}).get(LABEL)!=TOKEN or (len(target)==64 and o['Id']!=target) or o['Image']!=IMAGE or o['Config']['User']!='0:0' or h['Privileged'] or h['PidMode']!='host' or h['CgroupnsMode']!='host' or h['NetworkMode']!='none' or not h['ReadonlyRootfs'] or set(h['CapDrop'] or [])!={'ALL'} or caps!={'SYS_CHROOT','DAC_OVERRIDE','CHOWN'} or 'no-new-privileges' not in (h['SecurityOpt'] or []) or len(m)!=1 or m[0]['Source']!='/' or m[0]['Destination']!='/host' or not m[0]['RW']:raise RuntimeError('bridge identity/configuration mismatch')
 return o
def guard():
 info=json.loads(cmd(*D,'inspect','04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062').stdout)[0]
 if info['Name']!='/sf-owner-224a71d2db764249aa6cade3c1b39c80' or info['State']['Status']!='created' or info['State']['Pid']!=0 or (info['Config']['Labels'] or {}).get('org.software-factory.escape-spike')!='224a71d2db764249aa6cade3c1b39c80':raise RuntimeError('original guard changed')
 if cmd(*D,'info','--format','{{.ID}}').stdout.strip()!='56d25a60-5f64-4212-b904-e750067ac6a5' or cmd(*D,'version','--format','{{.Server.GitCommit}}').stdout.strip()!='3ce5872' or cmd('/usr/bin/systemctl','show','docker.service','-p','MainPID','--value').stdout.strip()!='2145':raise RuntimeError('daemon identity changed')
 services={name:cmd('/usr/bin/systemctl','is-active',name).stdout.strip() for name in ('docker.service','hermes-dashboard.service','hermes-gateway.service')}
 if any(v!='active' for v in services.values()):raise RuntimeError('existing service not active')
 return services
save('host-before.json',guard())
save('intent.json',{'name':NAME,'token':TOKEN,'operation':OP,'source_sha256':hashlib.sha256(SOURCE.encode()).hexdigest()})
wrapper="""import base64,fcntl,hashlib,io,json,os,pathlib,sys,zlib
source=zlib.decompress(base64.b85decode(SOURCE_LITERAL)).decode();op=OP_LITERAL;plan=json.loads(zlib.decompress(base64.b85decode(PLAN_LITERAL)))
if os.geteuid()!=0:raise RuntimeError('root required')
# First prove only CAP_CHOWN's required operation on a newly created inode.
# This file cannot replace or select an existing path; an open fd pins its identity.
if op=='capability-canary':
 root=pathlib.Path(ROOT_LITERAL);name='ownership-canary'
 fd=os.open(root/name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 os.fchown(fd,65534,65534)
 s=os.fstat(fd)
 if (s.st_uid,s.st_gid)!=(65534,65534):raise RuntimeError('ownership transition failed')
 os.fchown(fd,0,0);s=os.fstat(fd)
 if (s.st_uid,s.st_gid)!=(0,0):raise RuntimeError('ownership restoration failed')
 os.close(fd);os.unlink(root/name)
 print('RESULT '+json.dumps({'ownership_capability_verified':True}),flush=True)
else:
 if op not in ('plan','apply'):raise RuntimeError('invalid fixed operation')
 fd=os.memfd_create('sfactory-reviewed-identity',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
 data=source.encode();offset=0
 while offset<len(data):offset+=os.write(fd,data[offset:])
 fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
 namespace={'__name__':'sfactory_identity_install','__file__':'/proc/self/fd/'+str(fd)}
 exec(compile(source,namespace['__file__'],'exec'),namespace)
 host=namespace['Host'](source_digest=hashlib.sha256(data).hexdigest())
 if op=='plan':result=namespace['make_plan'](host)
 else:
  result=namespace['apply'](host,plan)
  if result is None:result={'identities_installed':True,'services_enabled':False}
 print('RESULT '+json.dumps(result,sort_keys=True),flush=True)
""".replace('SOURCE_LITERAL',repr(base64.b85encode(zlib.compress(SOURCE.encode(),9)).decode())).replace('OP_LITERAL',repr(OP)).replace('PLAN_LITERAL',repr(base64.b85encode(zlib.compress(json.dumps(PLAN,separators=(',',':')).encode(),9)).decode())).replace('ROOT_LITERAL',repr(str(ROOT)))
boot='import os;os.chroot("/host");os.chdir("/");os.execve("/usr/bin/python3",["/usr/bin/python3","-I","-B","-c",'+repr(wrapper)+'],{"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":"/nonexistent","LC_ALL":"C.UTF-8","SYSTEMD_IN_CHROOT":"0"})'
if len(boot.encode())>100000 or len(wrapper.encode())>100000:raise RuntimeError('bridge transport exceeds bounded argument size')
ident=None;complete=False
try:
 if cmd(*D,'info','--format','{{.ID}}').stdout.strip()!='56d25a60-5f64-4212-b904-e750067ac6a5':raise RuntimeError('daemon identity differs')
 r=cmd(*D,'create','--name',NAME,'--label',LABEL+'='+TOKEN,'--network','none','--read-only','--cap-drop','ALL','--cap-add','SYS_CHROOT','--cap-add','DAC_OVERRIDE','--cap-add','CHOWN','--security-opt','no-new-privileges','--pid','host','--cgroupns','host','--pids-limit','32','--memory','192m','--cpus','0.5','--user','0:0','--pull','never','--mount','type=bind,src=/,dst=/host','--entrypoint','python3',IMAGE,'-I','-B','-c',boot,timeout=60)
 ident=r.stdout.strip()
 if len(ident)!=64 or any(c not in '0123456789abcdef' for c in ident):raise RuntimeError('bridge create outcome unavailable')
 o=inspect(ident)
 if o is None or o['State']['Status']!='created' or o['State']['Pid']!=0:raise RuntimeError('bridge prestart state mismatch')
 save('manifest.json',{'id':ident,'name':NAME,'token':TOKEN})
 save('start-intent.json',{'id':ident})
 r=cmd(*D,'start','-a',ident,check=False,timeout=900)
 if len(r.stdout.encode())>65536 or len(r.stderr.encode())>8192:raise RuntimeError('bounded result unavailable')
 if r.returncode!=0:
  save('failure.json',{'returncode':r.returncode,'stderr':r.stderr})
  print(r.stderr,file=sys.stderr,end='');raise RuntimeError('root operation incomplete; retain exact state')
 o=inspect(ident)
 if o is None or o['State']['Running'] or o['State']['Pid']!=0 or o['State']['ExitCode']!=0:raise RuntimeError('bridge completion unresolved')
 lines=[s[7:] for s in r.stdout.splitlines() if s.startswith('RESULT ')]
 if len(lines)!=1:raise RuntimeError('operation result unavailable')
 result=json.loads(lines[0]);save('result.json',result)
 cmd(*D,'rm',ident)
 if inspect(ident) is not None:raise RuntimeError('bridge removal unresolved')
 save('cleanup.json',{'removed':ident});save('host-after.json',guard());complete=True
 print(json.dumps({'root':str(ROOT),'operation':OP,'result':result},sort_keys=True),flush=True)
finally:
 if not complete:print('RETAINED '+str(ROOT)+' bridge='+str(ident or NAME),file=sys.stderr,flush=True)
'''

ROOT_STOP_ADAPTER = r"""
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 spec,_=plan()
 return {'component':'root-stop','spec':spec,'plan_sha256':digest(spec),'source_sha256':host.source_digest}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed root-stop plan changed')
 sys.argv=['nuc_root_stop_install.py','apply',reviewed['plan_sha256']]
 main()
 return {'root_stop_installed':True,'services_enabled':False}
"""

ROOT_STOP_CANARY_ADAPTER = r"""
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'root-stop-canary','source_sha256':host.source_digest,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'binary_sha256':EXPECTED,'scope':'unique native worker and activated root stop; no frontend/provider'}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed root-stop canary changed')
 sys.argv=['nuc_root_stop_canary.py','--run']
 main()
 return {'root_stop_canary_passed':True,'frontend_activated':False}
"""

ROOT_STOP_CLEANUP_ADAPTER = r"""
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'root-stop-cleanup','source_sha256':host.source_digest,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'target_id':T,'scope':'exact expired native fixture and its test-activated root endpoints only'}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed root-stop cleanup changed')
 sys.argv=['nuc_root_stop_cleanup.py','--run']
 main()
 return {'expired_native_fixture_cleaned':True,'positive_canary':False}
"""

PG_STAGE_ADAPTER = r"""
_copy_stage=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 if os.path.lexists(DEST) or pathlib.Path('/var/lib/software-factory-goose/postgres-install-intent.json').exists() or pathlib.Path('/var/lib/software-factory-goose/postgres-install.json').exists():raise RuntimeError('stage destination or install record occupied')
 entries=manifest()
 return {'component':'pg-stage','source_sha256':host.source_digest,'manifest_sha256':MANIFEST_SHA256,'entry_count':len(entries),'destination':str(DEST),'scope':'copy PostgreSQL17.11 and pgvector0.8.7 only; no database or service start'}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed stage copy changed')
 state=pathlib.Path('/var/lib/software-factory-goose')
 def record(name,value):
  fd=os.open(state/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
  fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 record('postgres-install-intent.json',reviewed)
 _copy_stage()
 for entry in manifest():
  path=DEST/entry['path'];st=path.lstat()
  if st.st_uid!=0 or st.st_gid!=0 or stat.S_IMODE(st.st_mode)!=int(entry['mode'],8):raise RuntimeError('installed ownership/mode mismatch')
  if entry['type']=='file':
   if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:raise RuntimeError('installed file type mismatch')
   digest=hashlib.sha256()
   with path.open('rb') as f:
    for chunk in iter(lambda:f.read(65536),b''):digest.update(chunk)
   if digest.hexdigest()!=entry['sha256']:raise RuntimeError('installed digest mismatch')
  elif entry['type']=='directory':
   if not stat.S_ISDIR(st.st_mode):raise RuntimeError('installed directory mismatch')
  elif not stat.S_ISLNK(st.st_mode) or os.readlink(path)!=entry['target']:raise RuntimeError('installed symlink mismatch')
 result={'postgresql':'17.11','pgvector':'0.8.7','manifest_sha256':MANIFEST_SHA256,'source_sha256':host.source_digest,'installed_verified':True,'database_initialized':False,'services_enabled':False}
 record('postgres-install.json',result)
 return result
"""

ROOT_STOP_UPGRADE_ADAPTER = r"""
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 spec,_,_=plan();spec=json.loads(json.dumps(spec))
 return {'component':'root-stop-v2','source_sha256':host.source_digest,'spec':spec,'plan_sha256':digest(spec)}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed root-stop V2 upgrade changed')
 sys.argv=['nuc_root_stop_upgrade_v2.py','apply',reviewed['plan_sha256']]
 main()
 return {'root_stop_v2_installed':True,'services_enabled':False}
"""


BRAKE_FRONTEND_ADAPTER = r"""
_install_brake=apply
CANDIDATE=pathlib.Path('/tmp/sfactory-brake-candidate-efq15pi5/sfactory_brake_frontend')
CANDIDATE_SHA='c18388b4e5b1b26cf986bdb893baff8ce6ecc49f229923ff3075ab1bb95af232'
CLI_CANDIDATE=pathlib.Path('/tmp/sfactory-brake-candidate-efq15pi5/sfctl')
CLI_SHA='d83b2d93a8cc4b7fddce6c435bafbbdf2b4b2c925d52a713398c4282729f1c6e'
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 spec,_,_=plan(CANDIDATE,CANDIDATE_SHA,CLI_CANDIDATE,CLI_SHA)
 return {'component':'brake-frontend','source_sha256':host.source_digest,'spec':spec,'plan_sha256':digest(spec)}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed brake frontend plan changed')
 spec,binary,cli_binary=plan(CANDIDATE,CANDIDATE_SHA,CLI_CANDIDATE,CLI_SHA)
 _install_brake(spec,binary,cli_binary)
 return {'brake_frontend_installed':True,'sfctl_installed':True,'independent_key_provisioned':True,'services_enabled':False,'plan_sha256':digest(spec)}
"""


PG_HARDEN_ADAPTER = r"""
_harden_pg=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'pg-harden','source_sha256':host.source_digest,'spec':preflight(),'scope':'62 exact owned directory modes only; no service start'}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed PG hardening plan changed')
 _harden_pg(reviewed['spec'])
 return {'pg_tree_hardened':True,'receipt':json.loads(DONE.read_text()),'services_enabled':False}
"""

BRAKE_RECOVER_ADAPTER = r"""
_recover_brake=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 spec=plan()
 return {'component':'brake-recover','source_sha256':host.source_digest,'spec':spec,'plan_sha256':digest(spec)}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed brake recovery plan changed')
 _recover_brake(reviewed['spec'])
 return {'brake_frontend_recovered':True,'independent_key_copy_verified':True,'services_enabled':False,'plan_sha256':reviewed['plan_sha256']}
"""


OPERATOR_BRAKE_CANARY_ADAPTER = r"""
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'operator-brake-canary','source_sha256':host.source_digest,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'root_stop_sha256':EXPECTED,'frontend_sha256':FRONT_EXPECTED,'sfctl_sha256':SFCTL_EXPECTED,'scope':'fresh owned native worker only; actual operator frontend; no provider or existing task'}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed operator brake canary changed')
 sys.argv=['nuc_operator_brake_canary.py','--run']
 main()
 return {'operator_brake_canary_passed':True,'production_acceptance':False,'engine_reconciled':False}
"""


PRIVATE_RUNTIME_ADAPTER = r"""
_bootstrap_private=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'private-runtime','source_sha256':host.source_digest,'spec':preflight()}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed private runtime bootstrap changed')
 try:
  _bootstrap_private(reviewed['spec'])
 except BaseException:
  for suffix in ('intake.socket','worker.socket','runtime.service','register.service','genesis.service','createdb.service','initdb.service','restate.service','postgres.service','net.service','host-net.service'):
   name=NAME+suffix
   if name in CREATED_UNITS:
    try:systemctl('stop',name)
    except Exception:print('owned stop outcome unresolved: '+name,file=sys.stderr)
  raise
 return {'private_canary_bootstrapped':True,'production_accepted':False,'worker_execution_enabled':False,'units':list(units())}
"""


PRIVATE_INVENTORY_ADAPTER = r"""
import contextlib,io
_inventory_private=main
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 out=io.StringIO()
 sys.argv=['nuc_private_bootstrap_inventory.py','--inventory']
 with contextlib.redirect_stdout(out):_inventory_private()
 text=out.getvalue()
 if len(text.encode())>60000:raise RuntimeError('bounded private inventory unavailable')
 return {'component':'private-inventory','source_sha256':host.source_digest,'inventory':json.loads(text)}
"""


PRIVATE_RESOURCES_ADAPTER = r"""
_limit_private=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'private-resources','source_sha256':host.source_digest,'spec':plan()}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed private resource plan changed')
 _limit_private(reviewed['spec'])
 return {'private_resource_limits_installed':True,'units_started':False,'live_kernel_enforcement_verified':False}
"""


PRIVATE_RECOVERY_ADAPTER = r"""
_recover_private=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def stopped_groups():
 result={}
 for suffix in UNIT_SHA:
  if not suffix.endswith('.service'):continue
  name=NAME+suffix
  require(systemctl('show',name,'--property=Slice','--value')=='system.slice','unexpected old service slice')
  path=pathlib.Path('/sys/fs/cgroup/system.slice')/name
  try:fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  except FileNotFoundError:
   result[name]={'absent':True};continue
  try:
   st=os.fstat(fd);require(st.st_uid==0 and st.st_mode&0o022==0,'old service cgroup untrusted')
   eventfd=os.open('cgroup.events',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
   try:raw=os.read(eventfd,4097)
   finally:os.close(eventfd)
   require(len(raw)<=4096,'old cgroup events unavailable')
   events=dict(line.split() for line in raw.decode().splitlines())
   require(events.get('populated')=='0','old service cgroup populated')
   result[name]={'absent':False,'dev':st.st_dev,'ino':st.st_ino,'populated':False}
  finally:os.close(fd)
 return result

def make_plan(host):
 return {'component':'private-recover','source_sha256':host.source_digest,'spec':preflight(),'old_service_cgroups':stopped_groups()}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed private recovery changed')
 try:_recover_private(reviewed['spec'])
 except BaseException:
  if OWNED:
   for suffix in ('intake.socket','worker.socket','runtime.service','register.service','genesis.service','restate.service','postgres.service','net.service','host-net.service'):
    try:systemctl('stop',NAME+suffix)
    except Exception:print('owned stop outcome unresolved: '+NAME+suffix,file=sys.stderr)
  raise
 return {'private_canary_recovered':True,'preserved_postgres_system_id':SYSTEM_ID,'production_accepted':False,'worker_execution_enabled':False}
"""


PRIVATE_RESTART_ADAPTER = r"""
_restart_private=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'private-restart','source_sha256':host.source_digest,'spec':plan()}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed private restart plan changed')
 try:_restart_private(reviewed['spec'])
 except BaseException:
  for suffix in ('intake.socket','worker.socket','runtime.service'):
   subprocess.run(['/usr/bin/systemctl','stop',PREFIX+suffix],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
  raise
 return {'private_runtime_restart_verified':True,'completion':json.loads(DONE.read_text()),'shared_services_restarted':False}
"""


DEADLINE_INSTALL_ADAPTER = r"""
_install_deadline=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 spec,_=plan()
 return {'component':'deadline-install','source_sha256':host.source_digest,'spec':spec}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed deadline install changed')
 return _install_deadline(reviewed['spec'])
"""

DEADLINE_CANARY_ADAPTER = r"""
import types
_deadline=types.ModuleType('sfactory_reviewed_deadline')
exec(compile(ARM_SOURCE,'<reviewed-deadline-arm>','exec'),_deadline.__dict__)
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 for d in (_deadline.ROOT,_deadline.GRANTS,_deadline.STATE):_deadline.private_dir(d)
 _deadline.fixed_binary()
 p=__import__('subprocess').run(['/usr/bin/systemctl','is-active','software-factory-goose-root-stop.service'],capture_output=True,text=True,check=False)
 if p.stdout.strip() not in ('inactive','failed'):raise RuntimeError('root stop backend must be inactive for independent deadline canary')
 return {'component':'deadline-canary','source_sha256':host.source_digest,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'binary_sha256':_deadline.BINARY_SHA,'scope':'fresh native sleeper only, synthetic grant, root stop server inactive, no Docker/model'}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed native deadline canary changed')
 return native_deadline_canary(_deadline)
"""

DOCKER_DEADLINE_CANARY_ADAPTER = r"""
import types
_deadline=types.ModuleType('sfactory_reviewed_deadline')
exec(compile(ARM_SOURCE,'<reviewed-deadline-arm>','exec'),_deadline.__dict__)
_native=types.ModuleType('sfactory_reviewed_native_deadline')
exec(compile(NATIVE_SOURCE,'<reviewed-native-deadline>','exec'),_native.__dict__)
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 for directory in (_deadline.ROOT,_deadline.GRANTS,_deadline.STATE):_deadline.private_dir(directory)
 _deadline.fixed_binary();guard(_deadline)
 for path,expected in ((CANDIDATE,SHA),(NEGATIVE_CANDIDATE,NEGATIVE_SHA)):
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  with os.fdopen(fd,'rb') as f:
   s=os.fstat(f.fileno())
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=1000 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o700 or s.st_size>64*1024*1024:raise RuntimeError('candidate metadata mismatch')
   data=f.read(64*1024*1024+1)
   if len(data)!=s.st_size or hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('candidate digest mismatch')
 service=_deadline.run('/usr/bin/systemctl','show','software-factory-goose-root-stop.service','-p','ActiveState','--value')
 if service not in ('inactive','failed'):raise RuntimeError('root stop backend must be inactive')
 driver=_deadline.run(*D,'info','--format','{{.CgroupDriver}} {{.CgroupVersion}}')
 if driver!='systemd 2':raise RuntimeError('cgroup driver mismatch')
 return {'component':'docker-deadline-canary','source_sha256':host.source_digest,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'launcher_sha256':SHA,'negative_verifier_sha256':NEGATIVE_SHA,'deadline_sha256':_deadline.BINARY_SHA,'scope':'unique synthetic Docker positive and created-only negatives; no journal, model or provider; root stop backend inactive'}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed Docker deadline canary changed')
 positive=synthetic_docker_deadline_canary(_deadline,_native)
 negative=negative_controls(_deadline,_native)
 return {'positive':positive,'negative':negative,'scope':'synthetic only'}
"""


ROOT_LAUNCH_INSTALL_ADAPTER = r"""
def make_plan(host):
 spec,_=build_plan(host)
 return spec
"""


GRANT_SIDECAR_ADAPTER = r"""
_install_sidecar=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'grant-sidecar','source_sha256':host.source_digest,'spec':preflight()}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed grant sidecar changed')
 try:_install_sidecar(reviewed['spec'])
 except BaseException:
  if OWNED:
   for suffix in ('intake.socket','worker.socket','launch.socket','runtime.service','register.service'):
    try:ctl('stop',NAME+suffix)
    except Exception:print('owned sidecar stop outcome unresolved',file=sys.stderr)
  raise
 return {'grant_sidecar_installed':True,'existing_journal_preserved':True,'force_registration':False,'production_accepted':False,'engine_execution_enabled':False}
"""


GRANT_INVENTORY_ADAPTER = r"""
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'grant-inventory','source_sha256':host.source_digest,'inventory':inventory()}
"""


GRANT_RESUME_ADAPTER = r"""
_resume_grant=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'grant-resume','source_sha256':host.source_digest,'spec':plan()}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed retained sidecar resume changed')
 return _resume_grant(reviewed['spec'])
"""

GRANT_JOURNAL_CANARY_ADAPTER = r"""
_canary_apply=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'grant-journal-canary','source_sha256':host.source_digest,'spec':plan()}

def apply(host,reviewed):
 if reviewed!=make_plan(host):raise RuntimeError('reviewed grant journal canary changed')
 return _canary_apply(reviewed['spec'])
"""

SFCTL_REGISTRY_ADAPTER = r"""
_install_cli=apply
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 return {'component':'sfctl-registry','source_sha256':host.source_digest,'spec':plan()}

def apply(host,reviewed):
 if make_plan(host)!=reviewed:raise RuntimeError('reviewed CLI changed')
 return _install_cli(reviewed['spec'])
"""

def cli():
 args=sys.argv[1:];component='identity'
 if args and args[0] in ('--writer-full-init','--writer-package-verify','--writer-package-upgrade','--writer-cap0-diagnostic-v2','--registry-failed-launch-reconcile','--writer-cap0-diagnostic','--registry-intloop-failure-inventory','--registry-intloop-driver','--registry-intloop-reconcile','--callback-listener-canary','--native-cap0-install','--callback-upgrade-verify','--callback-package-upgrade','--callback-access-canary','--operator-brake-start','--registry-native-readiness','--registry-grant-install','--real-no-dispatch','--root-launch-install','--root-stop','--root-stop-canary','--root-stop-canary-v2','--root-stop-v2-receipts','--root-stop-cleanup','--pg-stage','--root-stop-v2','--brake-frontend','--brake-recover','--pg-harden','--operator-brake-canary','--private-runtime','--operator-brake-receipts','--private-inventory','--operator-peer-probe','--private-resources','--private-recover','--private-recovery-inventory','--private-resume2','--private-restart','--deadline-install','--deadline-canary','--docker-deadline-canary','--deadline-inventory','--grant-sidecar','--deadline-reconcile','--grant-inventory','--grant-admin-inspect','--grant-resume','--grant-journal-canary','--grant-expiry-canary','--real-repo','--real-sidecar','--real-activate','--real-attestation','--real-attestor-probe','--real-launch-prepare','--registry-sidecar','--registry-activate','--registry-attestation','--registry-attestor-probe','--registry-launch-prepare','--real-preclaim-readiness','--real-intloop-driver','--real-launch-access-probe','--real-failure-inventory','--real-static-diagnostic','--sfctl-registry','--relay-package','--worker-images','--openfile-canary'):component=args[0][2:];args=args[1:]
 if len(args) not in (1,2) or args[0] not in ('capability-canary','plan','apply'):raise SystemExit('usage: nuc_identity_bridge.py [--root-stop] capability-canary|plan|apply PLAN_JSON')
 operation=args[0]
 if (operation=='apply')!=(len(args)==2):raise SystemExit('apply requires the reviewed plan JSON')
 filename={'writer-full-init':'nuc_writer_full_init_host.py','writer-package-verify':'nuc_writer_package_verify.py','writer-package-upgrade':'nuc_writer_package_upgrade.py','writer-cap0-diagnostic-v2':'nuc_writer_cap0_diagnostic_v2.py','registry-failed-launch-reconcile':'nuc_registry_failed_launch_reconcile.py','writer-cap0-diagnostic':'nuc_writer_cap0_diagnostic.py','registry-intloop-failure-inventory':'nuc_registry_intloop_failure_inventory.py','registry-intloop-driver':'nuc_registry_intloop_driver.py','registry-intloop-reconcile':'nuc_registry_intloop_reconcile.py','callback-listener-canary':'nuc_callback_listener_canary.py','native-cap0-install':'nuc_native_cap0_install.py','callback-upgrade-verify':'nuc_callback_upgrade_verify.py','callback-package-upgrade':'nuc_callback_package_upgrade.py','callback-access-canary':'nuc_callback_access_canary.py','operator-brake-start':'nuc_operator_brake_start.py','registry-native-readiness':'nuc_registry_native_readiness_canary.py','registry-grant-install':'nuc_registry_grant_install.py','identity':'nuc_identity_install.py','real-no-dispatch':'nuc_real_no_dispatch_reconcile.py','root-launch-install':'nuc_root_launch_install.py','root-stop':'nuc_root_stop_install.py','root-stop-canary':'nuc_root_stop_canary.py','root-stop-canary-v2':'nuc_root_stop_canary_v2.py','root-stop-v2-receipts':'nuc_root_stop_v2_receipts.py','root-stop-cleanup':'nuc_root_stop_cleanup.py','pg-stage':'nuc_pg_stage_install.py','root-stop-v2':'nuc_root_stop_upgrade_v2.py','brake-frontend':'nuc_brake_frontend_install.py','brake-recover':'nuc_brake_frontend_recover.py','pg-harden':'nuc_pg_tree_harden.py','operator-brake-canary':'nuc_operator_brake_canary.py','private-runtime':'nuc_private_runtime_install.py','operator-brake-receipts':'nuc_operator_brake_receipts.py','private-inventory':'nuc_private_bootstrap_inventory.py','operator-peer-probe':'nuc_operator_peer_probe.py','private-resources':'nuc_private_resource_limits.py','private-recover':'nuc_private_bootstrap_recover.py','private-recovery-inventory':'nuc_private_recovery_inventory.py','private-resume2':'nuc_private_bootstrap_resume2.py','private-restart':'nuc_private_runtime_restart.py','deadline-install':'nuc_root_deadline_install.py','deadline-canary':'nuc_root_deadline_canary.py','docker-deadline-canary':'nuc_root_docker_deadline_canary.py','deadline-inventory':'nuc_root_deadline_inventory.py','grant-sidecar':'nuc_grant_sidecar_install.py','deadline-reconcile':'nuc_root_deadline_reconcile.py','grant-inventory':'nuc_grant_failed_inventory.py','grant-admin-inspect':'nuc_grant_admin_inspection.py','grant-resume':'nuc_grant_sidecar_resume.py','sfctl-registry':'nuc_sfctl_registry_install.py','relay-package':'nuc_relay_package_install.py','worker-images':'nuc_worker_images_install.py','openfile-canary':'nuc_openfile_canary.py','grant-journal-canary':'nuc_grant_journal_canary.py','grant-expiry-canary':'nuc_grant_expiry_canary.py','real-repo':'nuc_real_repo_install.py','real-sidecar':'nuc_real_sidecar_install.py','real-activate':'nuc_real_sidecar_activate.py','real-attestation':'nuc_real_process_attestation.py','real-attestor-probe':'nuc_real_attestor_probe.py','real-launch-prepare':'nuc_real_launch_prepare.py','registry-sidecar':'nuc_registry_sidecar_install.py','registry-activate':'nuc_registry_sidecar_activate.py','registry-attestation':'nuc_registry_process_attestation.py','registry-attestor-probe':'nuc_registry_attestor_probe.py','registry-launch-prepare':'nuc_registry_launch_prepare.py','real-preclaim-readiness':'nuc_real_preclaim_readiness.py','real-intloop-driver':'nuc_real_intloop_driver.py','real-launch-access-probe':'nuc_real_launch_access_probe.py','real-failure-inventory':'nuc_real_intloop_failure_inventory.py','real-static-diagnostic':'nuc_real_intloop_static_diagnostic.py'}[component]
 source=pathlib.Path(__file__).with_name(filename).read_text()
 if component in ('writer-package-upgrade','writer-cap0-diagnostic-v2','writer-cap0-diagnostic','registry-intloop-failure-inventory','registry-intloop-driver','callback-listener-canary','native-cap0-install','callback-upgrade-verify','callback-package-upgrade','callback-access-canary','operator-brake-start','registry-attestor-probe','registry-native-readiness','registry-grant-install','real-preclaim-readiness','real-failure-inventory','real-static-diagnostic'):
  module='nuc_grant_sidecar_install';body=pathlib.Path(__file__).with_name(module+'.py').read_text()
  source="import types,sys\n_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]=_m;exec(compile("+repr(body)+",'<reviewed-"+module+">','exec'),_m.__dict__)\n"+source
 if component=='sfctl-registry':
  dependency=pathlib.Path(__file__).with_name('nuc_grant_sidecar_install.py').read_text()
  source="import types,sys\n_m=types.ModuleType('nuc_grant_sidecar_install');sys.modules['nuc_grant_sidecar_install']=_m;exec(compile("+repr(dependency)+",'<reviewed-grant-tools>','exec'),_m.__dict__)\n"+source+SFCTL_REGISTRY_ADAPTER
 if component=='relay-package':
  dependency=pathlib.Path(__file__).with_name('nuc_worker_images_install.py').read_text()
  source="import types,sys\n_m=types.ModuleType('nuc_worker_images_install');sys.modules['nuc_worker_images_install']=_m;exec(compile("+repr(dependency)+",'<reviewed-worker-image-tools>','exec'),_m.__dict__)\n"+source
 if component=='openfile-canary':
  source=pathlib.Path(__file__).parent.joinpath('relay/nuc_openfile_canary_install.py').read_text()+'\n'+source
 if component in ('grant-resume','grant-journal-canary','grant-expiry-canary','real-sidecar','real-activate','real-attestation','real-attestor-probe','real-launch-prepare','real-intloop-driver','real-launch-access-probe','registry-sidecar','registry-activate','registry-attestation','registry-launch-prepare','writer-full-init'):
  dependencies='import types,sys\n'
  for module in ('nuc_grant_sidecar_install','nuc_grant_failed_inventory','nuc_grant_admin_inspection'):
   body=pathlib.Path(__file__).with_name(module+'.py').read_text()
   dependencies+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]=_m;exec(compile("+repr(body)+",'<reviewed-"+module+">','exec'),_m.__dict__)\n"
  if component in ('grant-journal-canary','grant-expiry-canary','real-sidecar','real-activate','real-attestation','real-attestor-probe','real-launch-prepare','real-intloop-driver','real-launch-access-probe','registry-sidecar','registry-activate','registry-attestation','registry-launch-prepare','writer-full-init'):
   body=pathlib.Path(__file__).with_name('nuc_grant_sidecar_resume.py').read_text()
   dependencies+="_m=types.ModuleType('nuc_grant_sidecar_resume');sys.modules['nuc_grant_sidecar_resume']=_m;exec(compile("+repr(body)+",'<reviewed-nuc_grant_sidecar_resume>','exec'),_m.__dict__)\n"
  if component in ('real-sidecar','real-activate','real-attestation','real-attestor-probe','real-launch-prepare','real-intloop-driver','real-launch-access-probe','registry-sidecar','registry-activate','registry-attestation','registry-launch-prepare','writer-full-init'):
   for module in ('nuc_real_repo_install','nuc_real_catalog'):
    body=pathlib.Path(__file__).with_name(module+'.py').read_text()
    dependencies+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]=_m;exec(compile("+repr(body)+",'<reviewed-"+module+">','exec'),_m.__dict__)\n"
  if component in ('real-activate','real-attestation','real-launch-prepare','registry-sidecar','registry-activate','registry-attestation','registry-launch-prepare','writer-full-init'):
   module='nuc_real_sidecar_install';body=pathlib.Path(__file__).with_name(module+'.py').read_text()
   dependencies+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]=_m;exec(compile("+repr(body)+",'<reviewed-"+module+">','exec'),_m.__dict__)\n"
  if component in ('real-attestation','real-launch-prepare','registry-sidecar','registry-activate','registry-attestation','registry-launch-prepare','writer-full-init'):
   module='nuc_real_sidecar_activate';body=pathlib.Path(__file__).with_name(module+'.py').read_text()
   dependencies+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]=_m;exec(compile("+repr(body)+",'<reviewed-"+module+">','exec'),_m.__dict__)\n"
  if component=='real-intloop-driver':
   module='nuc_real_preclaim_readiness';body=pathlib.Path(__file__).with_name(module+'.py').read_text()
   dependencies+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]=_m;exec(compile("+repr(body)+",'<reviewed-"+module+">','exec'),_m.__dict__)\n"
  if component in ('registry-activate','registry-attestation','registry-launch-prepare','writer-full-init'):
   module='nuc_registry_sidecar_install';body=pathlib.Path(__file__).with_name(module+'.py').read_text()
   dependencies+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]= _m;exec(compile("+repr(body)+",'<reviewed-registry-sidecar-install>','exec'),_m.__dict__)\n"
  if component in ('registry-attestation','registry-launch-prepare','writer-full-init'):
   module='nuc_registry_sidecar_activate';body=pathlib.Path(__file__).with_name(module+'.py').read_text()
   dependencies+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]= _m;exec(compile("+repr(body)+",'<reviewed-registry-sidecar-activate>','exec'),_m.__dict__)\n"
  if component=='writer-full-init':
   for module in ('nuc_registry_launch_prepare','nuc_writer_full_init_canary'):
    body=pathlib.Path(__file__).with_name(module+'.py').read_text()
    dependencies+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]= _m;exec(compile("+repr(body)+",'<reviewed-writer-canary>','exec'),_m.__dict__)\n"
  source=dependencies+source+'\n'+(GRANT_RESUME_ADAPTER if component=='grant-resume' else GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary',component))
 if component=='writer-cap0-diagnostic-v2':source+='\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','writer-cap0-diagnostic-v2')
 if component=='writer-cap0-diagnostic':source+='\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','writer-cap0-diagnostic')
 if component=='callback-listener-canary':source+='\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','callback-listener-canary')
 if component=='native-cap0-install':source+='\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','native-cap0-install')
 if component=='callback-access-canary':source+='\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','callback-access-canary')
 if component=='registry-attestor-probe':source+='\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','registry-attestor-probe')
 if component in ('callback-package-upgrade','callback-upgrade-verify'):
  deps='import types,sys\n'
  for module in ('nuc_worker_images_install','nuc_relay_package_install'):
   body=pathlib.Path(__file__).with_name(module+'.py').read_text()
   deps+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]=_m;exec(compile("+repr(body)+",'<reviewed-'+"+repr(module)+"+'>','exec'),_m.__dict__)\n"
  helper=pathlib.Path(__file__).parent.joinpath('relay/root-launch-host.py').read_bytes()
  module=pathlib.Path(__file__).parent.joinpath('relay/nuc_relay_systemd.py').read_bytes()
  if component=='callback-package-upgrade':source=deps+source+'\nHELPER_SOURCE='+repr(helper)+'\nMODULE_SOURCE='+repr(module)+'\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','callback-package-upgrade')
  else:source=deps+source+'\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','callback-upgrade-verify')
 if component=='registry-intloop-driver':source+='\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','registry-intloop-driver')
 if component=='writer-package-verify':
  deps='import types,sys\n'
  for module in ('nuc_grant_sidecar_install','nuc_worker_images_install','nuc_relay_package_install','nuc_callback_upgrade_verify'):
   body=pathlib.Path(__file__).with_name(module+'.py').read_text()
   deps+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]=_m;exec(compile("+repr(body)+",'<reviewed-'+"+repr(module)+"+'>','exec'),_m.__dict__)\n"
  source=deps+source+'\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','writer-package-verify')
 if component=='writer-package-upgrade':
  deps='import types,sys\n'
  for module in ('nuc_grant_sidecar_install','nuc_worker_images_install','nuc_relay_package_install','nuc_callback_package_upgrade'):
   body=pathlib.Path(__file__).with_name(module+'.py').read_text()
   deps+="_m=types.ModuleType("+repr(module)+");sys.modules["+repr(module)+"]=_m;exec(compile("+repr(body)+",'<reviewed-'+"+repr(module)+"+'>','exec'),_m.__dict__)\n"
  writer=pathlib.Path(__file__).parent.joinpath('relay/nuc_root_writer_service.py').read_bytes()
  source=deps+source+'\nSOURCE='+repr(writer)+'\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','writer-package-upgrade')
 if component=='operator-brake-start':
  body=pathlib.Path(__file__).with_name('nuc_operator_brake_canary.py').read_text()
  source="import types,sys\n_m=types.ModuleType('nuc_operator_brake_canary');sys.modules['nuc_operator_brake_canary']=_m;exec(compile("+repr(body)+",'<reviewed-brake-canary>','exec'),_m.__dict__)\n"+source+'\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','operator-brake-start')
 if component=='registry-grant-install':source+='\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','registry-grant-install')
 if component=='registry-native-readiness':
  support=pathlib.Path(__file__).with_name('nuc_grant_sidecar_install.py').read_text()
  readiness=pathlib.Path(__file__).with_name('nuc_registry_preclaim_readiness.py').read_text()
  source+='\nOLD_SOURCE='+repr(support)+'\nREADINESS_SOURCE='+repr(readiness)+'\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','registry-native-readiness')
 if component=='real-repo':source+='\n'+GRANT_JOURNAL_CANARY_ADAPTER.replace('grant-journal-canary','real-repo')
 if component=='root-launch-install':source+='\n'+ROOT_LAUNCH_INSTALL_ADAPTER
 if component=='root-stop':source+='\n'+ROOT_STOP_ADAPTER
 if component=='root-stop-canary':source+='\n'+ROOT_STOP_CANARY_ADAPTER
 if component=='root-stop-canary-v2':source+='\n'+ROOT_STOP_CANARY_ADAPTER.replace("'root-stop-canary'","'root-stop-canary-v2'").replace("'nuc_root_stop_canary.py'","'nuc_root_stop_canary_v2.py'")
 if component=='root-stop-cleanup':source+='\n'+ROOT_STOP_CLEANUP_ADAPTER
 if component=='pg-stage':source+='\n'+PG_STAGE_ADAPTER
 if component=='root-stop-v2':source+='\n'+ROOT_STOP_UPGRADE_ADAPTER
 if component=='brake-frontend':source+='\n'+BRAKE_FRONTEND_ADAPTER
 if component=='brake-recover':source+='\n'+BRAKE_RECOVER_ADAPTER
 if component=='pg-harden':source+='\n'+PG_HARDEN_ADAPTER
 if component=='operator-brake-canary':source+='\n'+OPERATOR_BRAKE_CANARY_ADAPTER
 if component=='private-runtime':source+='\n'+PRIVATE_RUNTIME_ADAPTER
 if component=='private-inventory':source+='\n'+PRIVATE_INVENTORY_ADAPTER
 if component=='private-recovery-inventory':source+='\n'+PRIVATE_INVENTORY_ADAPTER.replace("'private-inventory'","'private-recovery-inventory'").replace('nuc_private_bootstrap_inventory.py','nuc_private_recovery_inventory.py')
 if component=='private-resources':source+='\n'+PRIVATE_RESOURCES_ADAPTER
 if component=='private-restart':source+='\n'+PRIVATE_RESTART_ADAPTER
 if component=='deadline-install':source+='\n'+DEADLINE_INSTALL_ADAPTER
 if component=='grant-sidecar':source+='\n'+GRANT_SIDECAR_ADAPTER
 if component=='grant-inventory':source+='\n'+GRANT_INVENTORY_ADAPTER
 if component=='deadline-canary':source+='\nARM_SOURCE='+repr(pathlib.Path(__file__).with_name('nuc_root_deadline_arm.py').read_text())+'\n'+DEADLINE_CANARY_ADAPTER
 if component=='docker-deadline-canary':source+='\nARM_SOURCE='+repr(pathlib.Path(__file__).with_name('nuc_root_deadline_arm.py').read_text())+'\nNATIVE_SOURCE='+repr(pathlib.Path(__file__).with_name('nuc_root_deadline_canary.py').read_text())+'\n'+DOCKER_DEADLINE_CANARY_ADAPTER
 if component=='private-recover':source+='\n'+PRIVATE_RECOVERY_ADAPTER
 if component=='private-resume2':source+='\n'+PRIVATE_RECOVERY_ADAPTER.replace("'private-recover'","'private-resume2'")
 compile(source,'<reviewed-'+component+'>','exec')
 plan=json.loads(pathlib.Path(args[1]).read_text()) if operation=='apply' else None
 if operation=='apply' and (not isinstance(plan,dict) or plan.get('source_sha256')!=hashlib.sha256(source.encode()).hexdigest()):raise SystemExit('plan differs from reviewed source')
 code=REMOTE.replace('__SOURCE__',repr(source)).replace('__OP__',repr(operation)).replace('__PLAN__',repr(plan));compile(code,'<reviewed-remote>','exec')
 subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-I','-B','-'],input=code,text=True,check=True,timeout=950)

if __name__=='__main__':cli()
