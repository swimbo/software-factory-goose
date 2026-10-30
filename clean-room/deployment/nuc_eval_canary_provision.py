"""Create-only synthetic evaluator preparation; root review required before apply.

This installs no active service and never creates a production reconciliation.
The fixture catalog is separate and intentionally unusable by the production
bootstrap; a separately reviewed canary runtime must explicitly consume it.
"""
import hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGK';ALPH='0123456789ABCDEFGHJKMNPQRSTVWXYZ'
STATE=pathlib.Path('/var/lib/software-factory-goose');ROOT=old.ETC;SYSTEM=old.UNIT
BASE=STATE/'evaluator'/G;SNAP=BASE/'snapshot';BROKER=BASE/'broker';DEST=old.PREFIX/'evaluator';STAGE=pathlib.Path('/tmp/sfactory-evaluator-stage-20261030')
INTENT=ROOT/'evaluator-canary-provision-started.json';DONE=ROOT/'evaluator-canary-provision-complete.json';CAT=ROOT/'evaluator-canary-catalog.json'
REFERENCE=b'''import argparse\np=argparse.ArgumentParser()\np.add_argument("--uppercase",action="store_true")\np.add_argument("name",nargs="?",default="world")\na=p.parse_args()\ns="hello "+a.name\nprint(s.upper() if a.uppercase else s)\n'''
TESTS=b'''import subprocess,sys,unittest\nclass Smoke(unittest.TestCase):\n def test_default_greeting(self):\n  r=subprocess.run([sys.executable,"-I","-B","/work/hello.py"],capture_output=True,timeout=5)\n  self.assertEqual((r.returncode,r.stdout,r.stderr),(0,b"hello world\\n",b""))\n'''
FILES={'hello.py':REFERENCE,'test_hello.py':TESTS}
# Filled with fixed reviewed source hashes before any plan or host execution.
PINS={'nuc_registry_evaluator.py': '5c236c7ccf77b93d3c9ac89f05e9fc464afc8361e13e0aff26eafeb0fd4d1360', 'nuc_registry_eval_client.py': '818ed609a68421c30b3139c83f8d76b9023b03cd009b91908ac7266b40cfd971', 'nuc_registry_eval_coordinator.py': '2f51ca71361d096dc4ee187d5331f1c4450b64c206f9e5fff54fc0f69818b6b2', 'nuc_registry_eval_broker.py': '708cc142b92d62929f81a692d69be8412b9bfd7037a3020ca24fc54f06b9e8b2', 'nuc_registry_eval_backend.py': '20bf2a0da2e246071862dc479fdf10f5d3f1c1d14dd890d5daa640cd87437f81', 'nuc_registry_eval_bootstrap.py': 'fa4ccbcf60e0770411c56c3cce6c14c69c1f353c79928b1a7520f9762139efe8', 'nuc_registry_eval_deadline.py': 'ce390a0e56bd409ef05ccdb336748c4c6433bdaf2d59ff3533a9822185f0564e', 'nuc_registry_eval_server.py': 'de7b30017ad603e5a73af085a80c2731ed503f65ffd257ecc07ab4b0ef2b2da7', 'nuc_registry_eval_runtime.py': '68aa92b5c338b75e73a5c92cc42d53db5e6b321b0b63f6d0169079771bf8b67e', 'nuc_grant_sidecar_install.py': 'c8d3ebb2ba4707fdb2600564a1ef3bbc558e7c433cc09413df51e4d8bf87f3b6', 'nuc_registry_eval_canary_runtime.py': '25bbfe6cb6c92f40c0f33079ace3076582d23e1121dff60acd996a90aad8f5f3', 'nuc_registry_eval_canary_coordinator.py': '0fa1b9603507c66e66eb2968e1a077cf9ada589c302eec66c2edd32dd7f18710'}
def canon(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def target(i):
 n=int.from_bytes(hashlib.sha256(('sfactory-evaluator-canary-v1:'+G+':'+str(i)).encode()).digest()[:16],'big');return ''.join(ALPH[(n>>shift)&31] for shift in range(125,-1,-5))
def require(x,msg):
 if not x:raise RuntimeError(msg)
def sources():
 require(PINS and len(PINS)==12,'source pins unavailable');old.directory(STAGE,1000,1000,0o700);out={}
 for name,digest in PINS.items():
  require(re.fullmatch(r'[a-zA-Z0-9_.-]+',name) and re.fullmatch(r'[0-9a-f]{64}',digest),'invalid source pin')
  fd=os.open(STAGE/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(1000,1000,1,0o600) and st.st_size<=1_000_000,'source unavailable');old.noacl(fd);data=os.read(fd,1_000_001);require(len(data)==st.st_size and sha(data)==digest,'source changed');out[name]=data
  finally:os.close(fd)
 return out
def plan():
 require(os.geteuid()==0,'root required')
 for path,uid,gid,mode in ((ROOT,0,0,0o711),(STATE,0,0,0o711),(old.PREFIX,0,0,0o755),(SYSTEM,0,0,0o755),(ROOT/'tasks',0,0,0o700)) :old.directory(path,uid,gid,mode)
 src=sources();targets=[target(i) for i in range(1,23)];require(len(set(targets))==22 and G not in targets,'target collision')
 for path in (INTENT,DONE,CAT,BASE,DEST):require(not os.path.lexists(path),'fixture already exists')
 for name in targets:
  require(not os.path.lexists(ROOT/'tasks'/(name+'.create-intent.json')) and not os.path.lexists(ROOT/'tasks'/(name+'.json')) and not os.path.lexists(pathlib.Path('/sys/fs/cgroup')/('sfactory'+name.lower()+'.slice')) and not os.path.lexists(SYSTEM/('sfactory'+name.lower()+'.slice')),'target occupied')
  unit='sfactory'+name.lower()+'.slice'
  require(old.ctl('show',unit,'-p','ActiveState','--value')=='inactive' and old.ctl('show',unit,'-p','FragmentPath','--value')=='' and old.ctl('show',unit,'-p','DropInPaths','--value')=='','target active')
  for parent in ('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system'):
   for p in (pathlib.Path(parent)/unit,pathlib.Path(parent)/(unit+'.d'),pathlib.Path(parent)/'slice.d'):require(not os.path.lexists(p),'slice alias or drop-in occupied')
 return {'schema':1,'purpose':'synthetic-evaluator-canary-only','generation':G,'targets':targets,'source_sha256':{k:sha(v) for k,v in src.items()},'candidate_sha256':{k:sha(v) for k,v in FILES.items()},'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'scope':'provision only; no evaluator service or Docker start'}
def mkdir(path,mode,uid=0,gid=0):
 os.mkdir(path,mode);os.chmod(path,mode)
 if (uid,gid)!=(0,0):os.chown(path,uid,gid)
 old.syncdir(path.parent)
def write_group(path,data,mode,gid):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 try:
  v=memoryview(data)
  while v:
   n=os.write(fd,v);require(n>0,'short write');v=v[n:]
  os.fchmod(fd,mode);os.fchown(fd,0,gid);os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(path.parent)
def apply(approved):
 require(plan()==approved,'fixture plan changed');old.store(INTENT,canon(approved),0o600)
 parent=STATE/'evaluator'
 if not os.path.lexists(parent):mkdir(parent,0o700)
 old.directory(parent,0,0,0o700);mkdir(BASE,0o700);mkdir(SNAP,0o755);mkdir(BROKER,0o700);mkdir(DEST,0o710,0,2002)
 for n,b in FILES.items():old.store(SNAP/n,b,0o444)
 os.chmod(SNAP,0o555);old.syncdir(BASE);snapshot=os.stat(SNAP)
 for name,data in sources().items():write_group(DEST/name,data,0o440,2002)
 write_group(DEST/'scope.json',canon({'schema':1,'generation':G,'candidate_sha256':approved['candidate_sha256']}),0o440,2002)
 slice_text=b'[Unit]\nDescription=Software factory synthetic evaluator challenge\n[Slice]\nMemoryMax=128M\nTasksMax=32\nCPUQuota=50%\n'
 for target_id in approved['targets']:old.store(SYSTEM/('sfactory'+target_id.lower()+'.slice'),slice_text,0o644)
 old.ctl('daemon-reload');entries=[]
 for target_id in approved['targets']:
  name='sfactory'+target_id.lower()+'.slice';require(old.ctl('show',name,'-p','FragmentPath','--value')==str(SYSTEM/name) and old.ctl('show',name,'-p','DropInPaths','--value')=='' and old.ctl('show',name,'-p','Names','--value')==name and old.ctl('show',name,'-p','NeedDaemonReload','--value')=='no','slice identity mismatch')
  old.store(ROOT/'tasks'/(target_id+'.create-intent.json'),canon({'generation':G,'target':target_id}),0o600);old.ctl('start',name)
  cg=pathlib.Path('/sys/fs/cgroup')/name;st=os.stat(cg);quota=(cg/'cpu.max').read_text().split();require(st.st_uid==0 and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1 and (cg/'memory.max').read_text().strip()==str(128*1024**2) and (cg/'pids.max').read_text().strip()=='32' and len(quota)==2 and all(x.isdigit() for x in quota) and 2*int(quota[0])==int(quota[1]),'slice unavailable')
  task={'schema':1,'target_id':target_id,'task_id':G,'generation':target_id,'boot_id':approved['boot_id'],'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino};old.store(ROOT/'tasks'/(target_id+'.json'),canon(task),0o600)
  entries.append({'target':target_id,'task_id':G,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'snapshot_path':str(SNAP),'snapshot_dev':snapshot.st_dev,'snapshot_ino':snapshot.st_ino,'generation':G})
 cat={'schema':1,'purpose':'synthetic-evaluator-canary-only','generation':G,'snapshot_sha256':approved['candidate_sha256'],'challenges':entries,'boot_id':approved['boot_id']};old.store(CAT,canon(cat),0o600)
 result={'generation':G,'catalog_sha256':sha(canon(cat)),'targets':len(entries),'services_started':False,'containers_started':False,'fixture_only':True};old.store(DONE,canon(result),0o600);return result
