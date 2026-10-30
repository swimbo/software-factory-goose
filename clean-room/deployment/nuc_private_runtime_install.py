#!/usr/bin/env python3
"""Create-only, single-attempt NUC private-runtime canary bootstrap.

Requires independent source review and a root bridge before use. Failure retains
all created state and the started marker; it never retries or rolls back. This
fresh canary does not migrate a production journal or enable worker execution.
"""
import hashlib
import json
import os
import pathlib
import pwd
import secrets
import stat
import subprocess
import sys
import time

PREFIX = '/usr/local/libexec/software-factory-goose'
STATE = pathlib.Path('/var/lib/software-factory-goose/journal')
ETC = pathlib.Path('/etc/software-factory-goose')
RUN = pathlib.Path('/run/software-factory-goose')
UNIT = pathlib.Path('/etc/systemd/system')
NAME = 'software-factory-goose-private-'
PG = PREFIX + '/postgresql17'
SOURCES = {
 'private-runtime': ('/tmp/sfactory-runtime-build.PjU7pCOX/stripped/private_runtime.reservation3', '89002dbadf6eb1b0666247959bddbd8fa440a89b5d763c849465c11447fc471e'),
 'private-genesis': ('/tmp/sfactory-runtime-build.PjU7pCOX/stripped/private_genesis.reservation3', '7d6a3d4b67bc6f748ba45505fb96e40a0142655c7b9ddaafeba423b78bc9b6dc'),
 'private-restate': ('/tmp/sfactory-runtime-build.PjU7pCOX/stripped/private-restate', 'a45eba5044e331636b9da5a8f37fc901dec4cd3ccfcb10889241f76fe9c209db'),
}
ROLES = {'sfgoose-control':2000,'sfgoose-worker':2001,'sfgoose-eval':2002,'sfgoose-brake':2003,'sfgoose-journal':2004}
ANCHOR_BYTES = b'#!/usr/bin/python3\n"""Fixed systemd namespace anchor; started only by reviewed root units.\n\nWrites a single immutable observation and remains alive. Restart with a stale\nobservation fails closed; cleanup/reconciliation must be done explicitly.\n"""\nimport json\nimport os\nimport pathlib\nimport signal\nimport stat\nimport sys\n\nROOT = pathlib.Path(\'/run/software-factory-goose\')\n\n\ndef main():\n    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in (\'host\', \'private\'):\n        raise RuntimeError(\'anchor identity or role mismatch\')\n    status = pathlib.Path(\'/proc/self/status\').read_text().splitlines()\n    fields = dict(line.split(\':\', 1) for line in status if \':\' in line)\n    if any(int(fields[name].strip(), 16) for name in (\'CapEff\', \'CapPrm\', \'CapBnd\', \'CapAmb\')):\n        raise RuntimeError(\'namespace anchor must have empty capabilities\')\n    rootfd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)\n    try:\n        info = os.fstat(rootfd)\n        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:\n            raise RuntimeError(\'anchor directory untrusted\')\n        ns = os.stat(\'/proc/self/ns/net\')\n        data = json.dumps({\'version\': 1, \'role\': sys.argv[1], \'pid\': os.getpid(),\n                           \'uid\': os.geteuid(), \'netns_dev\': ns.st_dev, \'netns_ino\': ns.st_ino},\n                          sort_keys=True, separators=(\',\', \':\')).encode() + b\'\\n\'\n        fd = os.open(sys.argv[1] + \'-netns.json\', os.O_WRONLY | os.O_CREAT | os.O_EXCL |\n                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=rootfd)\n        try:\n            with os.fdopen(fd, \'wb\', closefd=False) as out:\n                out.write(data); out.flush(); os.fsync(fd)\n        finally:\n            os.close(fd)\n        os.fsync(rootfd)\n    finally:\n        os.close(rootfd)\n    while True:\n        signal.pause()\n\n\nif __name__ == \'__main__\':\n    main()\n'
ANCHOR_SHA256 = '3eb0162f005b961be44c381e142d16dc7ded34b2d5eca81ab9f7373fc1858123'
REGISTER_BYTES = b'#!/usr/bin/python3\n"""One non-retrying fixed registration, invoked only inside the private namespace."""\nimport http.client\nimport json\nimport os\nimport socket\nimport time\n\nif os.geteuid() != 2000:\n raise RuntimeError(\'registration identity mismatch\')\nfor port in (9081,9070):\n for _ in range(150):\n  try:\n   with socket.create_connection((\'127.0.0.1\',port),timeout=.1): break\n  except OSError: time.sleep(.1)\n else: raise RuntimeError(\'private service unavailable\')\nbody=json.dumps({\'uri\':\'http://127.0.0.1:9081\'},separators=(\',\',\':\')).encode()\nconn=http.client.HTTPConnection(\'127.0.0.1\',9070,timeout=10)\ntry:\n conn.request(\'POST\',\'/deployments\',body,{\'Content-Type\':\'application/json\'})\n response=conn.getresponse()\n if response.status not in (200,201): raise RuntimeError(\'registration rejected or unknown\')\n if len(response.read(65537)) > 65536: raise RuntimeError(\'registration response too large; unknown\')\nfinally:conn.close()\n'
REGISTER_SHA256 = '0f82712ecce31ff0985e265ab12e286bf5b3132730c43a473502686478daf244'
CREATED_UNITS = set()
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LANG':'C'}


def require(condition, message):
 if not condition: raise RuntimeError(message)


def checked_dir(path, uid, mode):
 s = os.lstat(path)
 require(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and stat.S_IMODE(s.st_mode) == mode, 'unsafe directory: '+str(path))
 for attr in ('system.posix_acl_access','system.posix_acl_default'):
  try: os.getxattr(path,attr,follow_symlinks=False)
  except OSError as e:
   import errno
   require(e.errno == errno.ENODATA, 'ACL inspection failed')
  else: raise RuntimeError('ACL forbidden: '+str(path))


def create(path, data, mode=0o644, uid=0, gid=0):
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 try:
  os.fchown(fd,uid,gid);os.fchmod(fd,mode)
  view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fsync(fd)
 finally: os.close(fd)
 pfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(pfd)
 finally:os.close(pfd)


def stream_pinned(path, digest, destination=None, max_bytes=300_000_000):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 out=None
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=max_bytes,'unsafe staged source')
  if destination is not None:
   out=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o755)
  count=0; sha=hashlib.sha256()
  while True:
   chunk=os.read(fd,65536)
   if not chunk:break
   count+=len(chunk);require(count<=st.st_size,'staged source grew');sha.update(chunk)
   if out is not None:
    view=memoryview(chunk)
    while view:
     n=os.write(out,view);require(n>0,'short copy');view=view[n:]
  require(count==st.st_size and sha.hexdigest()==digest,'staged digest mismatch')
  if out is not None:
   os.fchmod(out,0o755);os.fsync(out)
 finally:
  if out is not None:os.close(out)
  os.close(fd)
 if destination is not None:
  parent=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(parent)
  finally:os.close(parent)


def unit(body): return body.encode()


def units():
 net=NAME+'net.service';host=NAME+'host-net.service'
 common=f'BindsTo={net}\nAfter={net}\nJoinsNamespaceOf={net}\n'
 service='PrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nRestart=no\n'
 anchor=f'{PREFIX}/private-netns-anchor.py'
 result={
 host:unit(f'[Unit]\nDescription=Factory host namespace anchor\n[Service]\nType=simple\nUser=root\nPrivateNetwork=no\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nExecStart=/usr/bin/python3 -I -B {anchor} host\n'),
 net:unit(f'[Unit]\nDescription=Factory isolated namespace anchor\n[Service]\nType=simple\nUser=root\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nExecStart=/usr/bin/python3 -I -B {anchor} private\n'),
 NAME+'initdb.service':unit(f'[Unit]\n{common}[Service]\nType=oneshot\nUser=sfgoose-journal\n{service}Environment=LD_LIBRARY_PATH={PG}/lib\nExecStart={PG}/bin/initdb -D {STATE}/pgdata -U sfactory_admin --auth-local=peer --auth-host=scram-sha-256 --no-instructions\n'),
 NAME+'postgres.service':unit(f'[Unit]\n{common}[Service]\nType=simple\nUser=sfgoose-journal\n{service}Environment=LD_LIBRARY_PATH={PG}/lib\nExecStart={PG}/bin/postgres -D {STATE}/pgdata -h 127.0.0.1 -p 55432 -k {STATE}/socket\n'),
 NAME+'createdb.service':unit(f'[Unit]\n{common}Requires={NAME}postgres.service\nAfter={NAME}postgres.service\n[Service]\nType=oneshot\nUser=sfgoose-journal\n{service}Environment=LD_LIBRARY_PATH={PG}/lib\nExecStart={PG}/bin/createdb -h {STATE}/socket -p 55432 -U sfactory_admin sfactory\n'),
 NAME+'genesis.service':unit(f'[Unit]\n{common}Requires={NAME}postgres.service\nAfter={NAME}postgres.service\n[Service]\nType=oneshot\nUser=sfgoose-journal\n{service}ExecStart={PREFIX}/private-genesis\n'),
 NAME+'restate.service':unit(f'[Unit]\n{common}[Service]\nType=simple\nUser=sfgoose-journal\n{service}ExecStart={PREFIX}/private-restate --base-dir {STATE}/restate --node-name sfgoose-private --bind-ip 127.0.0.1 --listen-mode tcp --use-random-ports false --no-logo\n'),
 NAME+'intake.socket':unit(f'[Unit]\nBindsTo={net}\nAfter={net}\n[Socket]\nListenStream={RUN}/intake.sock\nSocketUser=root\nSocketGroup=1000\nSocketMode=0660\nFileDescriptorName=intake\nService={NAME}runtime.service\n'),
 NAME+'worker.socket':unit(f'[Unit]\nBindsTo={net}\nAfter={net}\n[Socket]\nListenStream={RUN}/worker.sock\nSocketUser=root\nSocketGroup=sfgoose-worker\nSocketMode=0660\nFileDescriptorName=worker\nService={NAME}runtime.service\n'),
 NAME+'runtime.service':unit(f'[Unit]\n{common}Requires={NAME}postgres.service {NAME}restate.service\nAfter={NAME}postgres.service {NAME}restate.service\n[Service]\nType=simple\nUser=sfgoose-control\n{service}Sockets={NAME}intake.socket {NAME}worker.socket\nExecStart={PREFIX}/private-runtime\n'),
 NAME+'register.service':unit(f'[Unit]\n{common}Requires={NAME}runtime.service {NAME}restate.service\nAfter={NAME}runtime.service {NAME}restate.service\n[Service]\nType=oneshot\nUser=sfgoose-control\n{service}ExecStart=/usr/bin/python3 -I -B {PREFIX}/private-register.py\n'),
 }
 return result


def systemctl(*args):
 result=subprocess.run(['/usr/bin/systemctl',*args],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
 require(result.returncode==0,'systemd operation failed; retain all state: '+args[0])
 return result.stdout.decode().strip()


def anchor(role):
 unitname=NAME+('host-net.service' if role=='host' else 'net.service')
 pid=int(systemctl('show',unitname,'--property=MainPID','--value'))
 path=RUN/(role+'-netns.json')
 for _ in range(100):
  if path.exists():break
  time.sleep(.05)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_size<=1024,'unsafe anchor observation')
  item=json.loads(os.read(fd,1025))
 finally:os.close(fd)
 require(item.get('version')==1 and item.get('role')==role and item.get('uid')==0 and item.get('pid')==pid and pid>1 and item.get('netns_ino',0)>0,'anchor identity mismatch')
 require(systemctl('is-active',unitname)=='active','anchor no longer active')
 return item


def no_file_acl(fd):
 import errno
 try:os.getxattr(fd,'system.posix_acl_access')
 except OSError as e:require(e.errno==errno.ENODATA,'file ACL unknown')
 else:raise RuntimeError('file ACL forbidden')


def verify_postgres_tree():
 # Root-reviewed tree manifest from the staged build; digest pins exact bytes.
 manifest_path='/etc/software-factory-goose/postgres-hardened-manifest.json'
 fd=os.open(manifest_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_size<=2_000_000,'unsafe PG manifest')
  no_file_acl(fd)
  data=bytearray()
  while len(data)<=2_000_000:
   chunk=os.read(fd,min(65536,2_000_001-len(data)))
   if not chunk:break
   data.extend(chunk)
  require(len(data)==st.st_size and hashlib.sha256(data).hexdigest()=='00052a70c5265a5748f51fef235c1c7f6c0fcf7f0d2fd267f71c533e47f4dfc8','PG manifest mismatch')
 finally:os.close(fd)
 receipt_path=ETC/'postgres-harden-complete.json'
 fd=os.open(receipt_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_size<=1024,'unsafe PG hardening receipt')
  no_file_acl(fd)
  receipt=json.loads(os.read(fd,1025))
 finally:os.close(fd)
 root_st=os.lstat(PG)
 require(receipt=={'format':1,'source_manifest_sha256':'39216b7ac1e082074b9e6098e5a3c94a0d706a1910cc302b9df0eddd4d9d23e5','hardened_manifest_sha256':'00052a70c5265a5748f51fef235c1c7f6c0fcf7f0d2fd267f71c533e47f4dfc8','directory_count':62,'tree_dev':root_st.st_dev,'tree_ino':root_st.st_ino},'PG hardening receipt mismatch')
 manifest=json.loads(data);require(manifest.get('format')==1,'PG manifest format mismatch')
 entries=manifest['entries'];expected={e['path'] for e in entries}
 require(len(expected)==len(entries),'duplicate PG manifest entry')
 root=pathlib.Path(PG);checked_dir(root,0,0o755)
 found=set()
 for directory,dirs,files in os.walk(root,followlinks=False):
  prefix=pathlib.Path(directory).relative_to(root)
  for name in dirs+files:found.add(str(prefix/name))
 require(found==expected,'installed PG tree differs from manifest')
 for entry in entries:
  path=root/entry['path'];st=os.lstat(path);mode=int(entry['mode'],8)
  require(st.st_uid==0 and stat.S_IMODE(st.st_mode)==mode,'installed PG owner/mode mismatch')
  if entry['type']=='symlink':
   require(stat.S_ISLNK(st.st_mode) and os.readlink(path)==entry['target'] and '/' not in entry['target'],'installed PG symlink mismatch')
   continue
  if entry['type']=='directory':
   require(stat.S_ISDIR(st.st_mode) and not mode&0o022,'installed PG directory mismatch')
   attrs=('system.posix_acl_access','system.posix_acl_default')
  else:
   require(entry['type']=='file' and stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==entry['size'] and not mode&0o022,'installed PG file mismatch')
   stream_pinned(path,entry['sha256'],max_bytes=max(entry['size'],1))
   attrs=('system.posix_acl_access',)
  for attr in attrs:
   try:os.getxattr(path,attr,follow_symlinks=False)
   except OSError as e:
    import errno
    require(e.errno==errno.ENODATA,'installed PG ACL unknown')
   else:raise RuntimeError('installed PG ACL forbidden')
 return '00052a70c5265a5748f51fef235c1c7f6c0fcf7f0d2fd267f71c533e47f4dfc8'


def postgres_system_id(pgdata):
 env=dict(ENV);env['LD_LIBRARY_PATH']=PG+'/lib'
 result=subprocess.run([PG+'/bin/pg_controldata',str(pgdata)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
 require(len(result.stdout)<=65536,'postgres identity output too large')
 lines=[line.split(':',1)[1].strip() for line in result.stdout.decode().splitlines() if line.startswith('Database system identifier:')]
 require(len(lines)==1 and lines[0].isdigit() and 0<int(lines[0])<2**64,'postgres identity unavailable')
 return lines[0]


def preflight():
 require(os.geteuid()==0,'root required')
 for role,uid in ROLES.items():
  item=pwd.getpwnam(role)
  require(item.pw_uid==uid and item.pw_gid==uid and item.pw_shell=='/usr/sbin/nologin','identity mismatch')
 require(pwd.getpwnam('bo').pw_uid==1000 and pwd.getpwnam('bo').pw_gid==1000,'operator identity mismatch')
 root_dirs=[pathlib.Path(p) for p in ('/','/etc','/etc/systemd','/etc/systemd/system','/usr','/usr/local','/usr/local/libexec','/usr/lib','/var','/var/lib','/run')]
 for path in root_dirs:checked_dir(path,0,0o755)
 checked_dir(pathlib.Path('/var/lib/software-factory-goose'),0,0o711)
 checked_dir(pathlib.Path('/tmp'),0,0o1777)
 checked_dir(pathlib.Path('/tmp/sfactory-pg1711-build.vfNv9w4h'),1000,0o700)
 checked_dir(pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX'),1000,0o700)
 checked_dir(pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX/stripped'),1000,0o700)
 for path,uid,mode in [(ETC,0,0o711),(RUN,0,0o755),(STATE,2004,0o700),(pathlib.Path(PREFIX),0,0o755),(UNIT,0,0o755)]:checked_dir(path,uid,mode)
 require(not list(STATE.iterdir()),'journal root not fresh')
 required=[ETC/'private-bootstrap-started',ETC/'private-bootstrap-complete',ETC/'private-genesis.json',ETC/'runtime.json',ETC/'evidence.json',RUN/'host-netns.json',RUN/'private-netns.json',RUN/'intake.sock',RUN/'worker.sock',pathlib.Path(PREFIX)/'private-netns-anchor.py',pathlib.Path(PREFIX)/'private-register.py']
 required += [pathlib.Path(PREFIX)/name for name in SOURCES]
 required += [UNIT/name for name in units()]
 require(not any(os.path.lexists(p) for p in required),'bootstrap destination occupied')
 # Do not inherit aliases or any unit-specific, dash-prefix or generic drop-ins.
 result=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
 paths=[pathlib.Path(p) for p in result.stdout.decode().splitlines()]
 require(paths and all(str(p).startswith(('/etc/','/run/','/usr/')) for p in paths),'unit search path mismatch')
 for name in units():
  require(systemctl('show',name,'--property=LoadState','--value')=='not-found','systemd unit already exists')
  stem,kind=name.rsplit('.',1)
  candidates=[name,name+'.d',kind+'.d']
  candidates += [stem[:i+1]+'.'+kind+'.d' for i,c in enumerate(stem) if c=='-']
  for directory in paths:
   for candidate in candidates:
    require(not os.path.lexists(directory/candidate),'unit alias or drop-in collision')
 pg_tree_sha256=verify_postgres_tree()
 for path,digest in SOURCES.values():stream_pinned(path,digest)
 require(hashlib.sha256(ANCHOR_BYTES).hexdigest()==ANCHOR_SHA256 and hashlib.sha256(REGISTER_BYTES).hexdigest()==REGISTER_SHA256,'embedded helper mismatch')
 observed={}
 for path in root_dirs+[ETC,RUN,STATE,pathlib.Path(PREFIX),pathlib.Path('/var/lib/software-factory-goose')]:
  st=os.lstat(path);observed[str(path)]={'dev':st.st_dev,'ino':st.st_ino,'uid':st.st_uid,'mode':stat.S_IMODE(st.st_mode)}
 return {'format':1,'machine_sha256':hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes().strip()).hexdigest(),
         'directories':observed,'roles':ROLES,'sources':{n:d for n,(_,d) in SOURCES.items()},
         'units':{n:hashlib.sha256(data).hexdigest() for n,data in units().items()},
         'anchor_sha256':ANCHOR_SHA256,'registration_sha256':REGISTER_SHA256,'postgres_tree_sha256':pg_tree_sha256,
         'scope':'fresh private canary only; no worker launch or production acceptance'}


def apply(plan):
 require(preflight()==plan,'reviewed plan changed; no changes made')
 anchor_data=ANCHOR_BYTES;register_data=REGISTER_BYTES
 nonce=secrets.token_hex(32)
 create(ETC/'private-bootstrap-started',json.dumps({'nonce':nonce,'machine_sha256':plan['machine_sha256'],'state':'started'},sort_keys=True).encode()+b'\n',0o600)
 for name,(path,digest) in SOURCES.items():stream_pinned(path,digest,pathlib.Path(PREFIX)/name)
 create(pathlib.Path(PREFIX)/'private-netns-anchor.py',anchor_data,0o755)
 create(pathlib.Path(PREFIX)/'private-register.py',register_data,0o755)
 for name,data in units().items():
  create(UNIT/name,data,0o644); CREATED_UNITS.add(name)
 systemctl('daemon-reload')
 systemctl('start',NAME+'host-net.service');systemctl('start',NAME+'net.service')
 h=anchor('host');n=anchor('private')
 require((h['netns_dev'],h['netns_ino']) != (n['netns_dev'],n['netns_ino']),'private namespace equals host')
 request={'schema_version':1,'repository':'fixture','target_ref':'refs/heads/main','base_revision':'a'*40,'intent':'build fixture','acceptance_criteria':['passes fixture']}
 facts={'spec_clarity':1.0,'blast_radius':0.0,'novelty':0.0,'reversibility':0.0,'has_codified_knowledge':True,'fatal':False}
 evidence=json.dumps({'principal':'fixture-submitter','request':request,'facts':facts},sort_keys=True,separators=(',',':')).encode()+b'\n'
 config={'service_uid':2000,'operator_uid':1000,'worker_uid':2001,'evaluator_uid':2002,'brake_uid':2003,'journal_uid':2004,'operator_socket_gid':1000,'worker_socket_gid':2001,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'namespace_dev':n['netns_dev'],'namespace_ino':n['netns_ino'],'host_namespace_dev':h['netns_dev'],'host_namespace_ino':h['netns_ino'],'sdk_port':9081,'restate_ingress_port':8080,'postgres_port':55432,'principal':'fixture-submitter','worker_id':'fixture-worker','queue_id':'runtime-queue','intent_id':'01ARZ3NDEKTSV4RRFFQ69G5FAZ','task_id':'01ARZ3NDEKTSV4RRFFQ69G5FAY','request':request,'facts':facts,'evidence_sha256':hashlib.sha256(evidence).hexdigest()}
 create(ETC/'evidence.json',evidence);create(ETC/'runtime.json',json.dumps(config,sort_keys=True,separators=(',',':')).encode()+b'\n')
 systemctl('start',NAME+'initdb.service')
 pgdata=STATE/'pgdata';checked_dir(pgdata,2004,0o700)
 # initdb created these paths in this invocation; replacement is scoped to that fresh data dir.
 for name,data in {'pg_hba.conf':b'local all sfactory_admin peer map=factory\nhost sfactory sfactory 127.0.0.1/32 trust\nhost all all 127.0.0.1/32 reject\nhost all all ::1/128 reject\n','pg_ident.conf':b'factory sfgoose-journal sfactory_admin\n'}.items():
  path=pgdata/name;st=os.lstat(path);require(stat.S_ISREG(st.st_mode) and st.st_uid==2004 and st.st_nlink==1,'unsafe fresh PG config')
  fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   actual=os.fstat(fd);require((actual.st_dev,actual.st_ino,actual.st_uid,actual.st_nlink)==(st.st_dev,st.st_ino,2004,1),'fresh PG config changed')
   os.ftruncate(fd,0);view=memoryview(data)
   while view:
    count=os.write(fd,view);require(count>0,'short PG config write');view=view[count:]
   os.fsync(fd)
  finally:os.close(fd)
 os.mkdir(STATE/'socket',0o700);os.chown(STATE/'socket',2004,2004)
 cluster_id=postgres_system_id(pgdata)
 pg_stat=os.lstat(pgdata)
 systemctl('start',NAME+'postgres.service')
 # Explicit readiness probe; no SQL mutation while waiting.
 for _ in range(100):
  if (STATE/'socket'/'.s.PGSQL.55432').exists():break
  time.sleep(.1)
 else:raise RuntimeError('PostgreSQL socket unavailable')
 systemctl('start',NAME+'createdb.service');systemctl('start',NAME+'genesis.service')
 require(postgres_system_id(pgdata)==cluster_id,'postgres cluster identity changed')
 after=os.lstat(pgdata)
 require((pg_stat.st_dev,pg_stat.st_ino)==(after.st_dev,after.st_ino),'postgres directory identity changed')
 for name,expected in [('private-genesis-started',b'genesis started; never automatically replay\n'),('private-genesis-complete',b'fresh projection genesis completed\n')]:
  path=STATE/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==2004 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and os.read(fd,129)==expected,'genesis receipt mismatch')
  finally:os.close(fd)
 receipt={'bootstrap_nonce':nonce,'boot_id':config['boot_id'],'machine_sha256':plan['machine_sha256'],'postgres_system_id':cluster_id,'pgdata_dev':pg_stat.st_dev,'pgdata_ino':pg_stat.st_ino,'namespace_dev':n['netns_dev'],'namespace_ino':n['netns_ino'],'genesis_sha256':SOURCES['private-genesis'][1]}
 create(ETC/'private-genesis.json',json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()+b'\n',0o644)
 systemctl('start',NAME+'restate.service');systemctl('start',NAME+'intake.socket');systemctl('start',NAME+'worker.socket');systemctl('start',NAME+'runtime.service')
 # Registration may have an ambiguous outcome; this single-attempt bootstrap never retries.
 systemctl('start',NAME+'register.service')
 anchor('host');anchor('private')
 create(ETC/'private-bootstrap-complete',b'private canary bootstrap completed; acceptance tests required\n',0o644)
 print('Private canary bootstrap completed; acceptance and launcher integration remain open.')

if __name__=='__main__':
 try:
  if sys.argv==[sys.argv[0],'--plan']:
   print(json.dumps(preflight(),sort_keys=True,indent=2))
  elif sys.argv==[sys.argv[0],'--apply']:
   raw=sys.stdin.buffer.read(1_000_001);require(len(raw)<=1_000_000,'plan too large')
   apply(json.loads(raw))
  else:raise RuntimeError('expected --plan or --apply')
 except Exception:
  # Stop only exact units this attempt created. Never remove files or database state.
  # A failed/timed-out stop is unresolved; do not retry bootstrap automatically.
  for suffix in ('intake.socket','worker.socket','runtime.service','register.service',
                 'restate.service','postgres.service','net.service','host-net.service'):
   name=NAME+suffix
   if name in CREATED_UNITS:
    try: systemctl('stop',name)
    except Exception: print('owned stop outcome unresolved: '+name,file=sys.stderr)
  raise
