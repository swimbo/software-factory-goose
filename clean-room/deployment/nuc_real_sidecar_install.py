"""Fresh fixed third SDK installation; never forces or repeats registration."""
import hashlib,json,os,pathlib,stat,subprocess,uuid
import nuc_grant_sidecar_install as old
import nuc_grant_sidecar_resume as resume
import nuc_real_catalog as catalog
import nuc_real_repo_install as repo

NAME='software-factory-goose-real-';BIN=old.PREFIX/'private-real-sidecar'
SOURCE=pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX/stripped/private-real-sidecar')
SOURCE_SHA='dea4b1ac448b7ab9f6e19e64230a1b252190200728ea35e4e157978d7e3b8fc8'
START=old.ETC/'real-sidecar-started.json';DONE=old.ETC/'real-sidecar-complete.json';MARKER=old.ETC/'real-bootstrap-complete'
CONFIG=old.ETC/'real-runtime.json';EVIDENCE=old.ETC/'real-evidence.json';REGISTER=old.PREFIX/'private-real-register.py'
EXPECTED_BASE='8462f440665066b35fffa0c0e42686065758f2e6';EXPECTED_CAT='cc5c4ae8ec34730f037fddefcb7b6d92fd4eab2bc1ac06dabd92abd747c1f1b7'
REGISTER_SOURCE=old.REGISTER.replace(b'9082',b'9083').replace(b'GRANT_REGISTRATION ',b'REAL_REGISTRATION ')

def require(x,msg):
 if not x:raise RuntimeError(msg)
def units():
 out={}
 for name,data in old.units().items():
  n=name.replace(old.NAME,NAME)
  text=data.decode().replace(old.NAME,NAME).replace('grant-intake.sock','real-intake.sock').replace('grant-worker.sock','real-worker.sock').replace('launch-grant.sock','real-launch-grant.sock').replace('private-grant-sidecar','private-real-sidecar').replace('private-grant-register.py','private-real-register.py')
  if n.endswith('.service'):text=text.replace('User=sfgoose-control\n','User=sfgoose-control\nGroup=sfgoose-control\n')
  out[n]=text.encode()
 return out

def repo_probe(args):
 unit='sfactory-real-repo-inspect-'+uuid.uuid4().hex+'.service'
 argv=['/usr/bin/systemd-run','--unit='+unit,'--collect','--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=MemoryMax=128M','--property=TasksMax=32','--property=RuntimeMaxSec=15s','/usr/bin/git','-C',str(repo.REPO),*args]
 return subprocess.run(argv,env=old.ENV,capture_output=True,timeout=25,check=False)

def generated():
 before=json.loads(old.read(old.ETC/'runtime.json',0o644,'53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6'))
 receipt=json.loads(old.read(repo.DONE,0o600));require(receipt.get('baseline')==EXPECTED_BASE and receipt.get('repo')==str(repo.REPO) and receipt.get('files')=={k:hashlib.sha256(v.encode()).hexdigest() for k,v in repo.FILES.items()},'repository receipt mismatch')
 repo.safe_dir(repo.PARENT,0,0o711);repo.safe_dir(repo.REPO,2000,0o700)
 for args,expected in [(['rev-parse','HEAD'],EXPECTED_BASE),(['status','--porcelain'],''),(['ls-tree','-r','--name-only','HEAD'],'AGENTS.md\nREADME.md\nrequirements.md')]:
  p=repo_probe(args);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192 and p.stdout.decode().strip()==expected,'repository git state changed')
 for name,value in repo.FILES.items():
  fd=os.open(repo.REPO/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   s=os.fstat(fd);data=os.read(fd,8193);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(2000,2000,1,0o600) and data==value.encode(),'repository evidence changed')
  finally:os.close(fd)
 config,evidence=catalog.build(before,EXPECTED_BASE);require(config['launch_scope']['catalog_sha256']==EXPECTED_CAT,'catalog fingerprint mismatch')
 return json.dumps(config,sort_keys=True,separators=(',',':')).encode()+b'\n',evidence

def source_info():
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_nlink,stat.S_IMODE(s.st_mode))==(1000,1,0o700) and s.st_size<100_000_000,'source mismatch');h=hashlib.sha256()
  while True:
   b=os.read(fd,65536)
   if not b:break
   h.update(b)
  require(h.hexdigest()==SOURCE_SHA,'binary source digest mismatch');return {'dev':s.st_dev,'ino':s.st_ino,'size':s.st_size,'sha256':SOURCE_SHA}
 finally:os.close(fd)

def plan():
 require(os.geteuid()==0,'root required')
 for path,uid,gid,mode in [(old.ETC,0,0,0o711),(old.RUN,0,0,0o755),(old.UNIT,0,0,0o755),(old.PREFIX,0,0,0o755),(SOURCE.parent,1000,1000,0o700)]:old.directory(path,uid,gid,mode)
 destinations=[START,DONE,MARKER,CONFIG,EVIDENCE,BIN,REGISTER]+[old.UNIT/n for n in units()]+[old.RUN/n for n in ('real-intake.sock','real-worker.sock','real-launch-grant.sock')]
 require(not any(os.path.lexists(p) for p in destinations),'real sidecar destination exists')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'systemd paths unavailable')
 for name in units():
  require(old.ctl('show',name,'--property=LoadState','--value')=='not-found','unit name occupied')
  for parent in map(pathlib.Path,paths):
   for p in (parent/name,parent/(name+'.d'),parent/'service.d',parent/'socket.d',parent/'software-factory-goose-.service.d',parent/'software-factory-goose-real-.service.d'):
    require(not os.path.lexists(p),'unit alias/drop-in occupied')
 config,evidence=generated();snapshot=old.old_snapshot();sidecar=old.sidecar_running();resume.old_inspect()
 return {'config_sha256':hashlib.sha256(config).hexdigest(),'evidence_sha256':hashlib.sha256(evidence).hexdigest(),'catalog_sha256':EXPECTED_CAT,'baseline':EXPECTED_BASE,'source':source_info(),'units':{n:hashlib.sha256(v).hexdigest() for n,v in units().items()},'register_sha256':hashlib.sha256(REGISTER_SOURCE).hexdigest(),'old':snapshot,'prior_sidecar':sidecar,'scope':'third URI, no force, no engine/provider'}

def verify_loaded():
 for name in units():
  output=old.ctl('show',name,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,MemoryMax,TasksMax,CPUQuotaPerSecUSec','--no-pager')
  properties=dict(line.split('=',1) for line in output.splitlines())
  require(properties.get('LoadState')=='loaded' and properties.get('ActiveState')=='inactive' and properties.get('Names')==name and properties.get('FragmentPath')==str(old.UNIT/name) and properties.get('DropInPaths','')=='','real unit loaded identity mismatch')
  if name.endswith('.service'):
   require(properties.get('MainPID')=='0' and properties.get('MemoryMax')==str(512*1024**2) and properties.get('TasksMax')=='128' and properties.get('CPUQuotaPerSecUSec') in ('1s','1000000us'),'real service resource mismatch')

def apply(approved):
 require(plan()==approved,'real sidecar plan changed')
 old.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 # This helper only provisions stopped files. A separately reviewed registration/attestation
 # step must start sockets and SDK; no unverified catalog is exposed by this operation.
 config,evidence=generated();old.store(CONFIG,config);old.store(EVIDENCE,evidence)
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);out=os.open(BIN,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o755)
 try:
  h=hashlib.sha256();total=0
  while True:
   block=os.read(fd,65536)
   if not block:break
   total+=len(block);h.update(block);view=memoryview(block)
   while view:
    n=os.write(out,view);require(n>0,'short binary write');view=view[n:]
  require(total==approved['source']['size'] and h.hexdigest()==SOURCE_SHA,'source changed');os.fchmod(out,0o755);os.fsync(out)
 finally:os.close(fd);os.close(out)
 old.syncdir(old.PREFIX);old.store(REGISTER,REGISTER_SOURCE,0o755)
 for n,data in units().items():old.store(old.UNIT/n,data)
 old.ctl('daemon-reload');verify_loaded()
 require(old.old_snapshot()==approved['old'] and old.sidecar_running()==approved['prior_sidecar'],'existing services changed')
 result={'files_installed':True,'registered':False,'started':False,'production_accepted':False,'catalog_sha256':EXPECTED_CAT}
 old.store(DONE,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return result
