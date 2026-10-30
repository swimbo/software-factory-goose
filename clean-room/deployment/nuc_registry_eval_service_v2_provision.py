"""Create fixed per-generation evaluator socket/service after root catalog proof."""
import hashlib,json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_eval_snapshot_provision as snapshot
import nuc_registry_transition_gate as gate
ROOT=old.ETC;RUN=old.RUN;PREFIX=old.PREFIX/'evaluator-production-v2';UNIT=old.UNIT
RUNTIME=PREFIX/'nuc_registry_eval_runtime_per_generation.py'
def require(v,m):
 if not v:raise RuntimeError(m)
def sha(v):return hashlib.sha256(v).hexdigest()
def bodies(g):
 name='sfactoryevalbroker'+g.lower();parent=RUN/'evaluator-production'/g
 socket=(f'[Unit]\nDescription=Factory evaluator for {g}\n[Socket]\nListenStream={parent}/broker.sock\nSocketUser=root\nSocketGroup=sfgoose-eval\nSocketMode=0660\nFileDescriptorName=evaluator\nAccept=no\nRemoveOnStop=yes\nService={name}.service\n').encode()
 service=(f'[Unit]\nRequires={name}.socket\nAfter={name}.socket\n[Service]\nType=exec\nUser=root\nGroup=root\nSlice=system.slice\nSockets={name}.socket\nExecStart=/usr/bin/python3 -I -B {RUNTIME}\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=/var/lib/software-factory-goose/evaluator /var/lib/software-factory-goose/stop /sys/fs/cgroup\nMemoryMax=256M\nTasksMax=32\nCPUQuota=100%\nLimitCORE=0\nRestart=no\nUMask=0077\n').encode()
 return name,socket,service

def _plan():
 snapshot.trusted_ancestry(ROOT);snapshot.trusted_ancestry(RUN);g,reg,scope=snapshot.selected()
 complete=json.loads(old.read(ROOT/(g+'.evaluator-catalog-complete.json'),0o600));raw=old.read(ROOT/(g+'.evaluator-catalog.json'),0o600,complete['catalog_sha256']);cat=json.loads(raw)
 require(complete.get('generation')==g and complete.get('fixture_only') is False and complete.get('targets')==22 and cat.get('generation')==g and len(cat.get('challenges',[]))==22,'catalog unavailable')
 # An independently pinned package manifest is a mandatory prerequisite.
 manifest=json.loads(old.read(ROOT/'evaluator-package-v2.json',0o600));pins=manifest.get('files');require(manifest.get('schema')==1 and isinstance(pins,dict) and set(pins)=={'nuc_grant_sidecar_install.py','nuc_registry_eval_runtime_per_generation.py','nuc_registry_eval_bootstrap_per_generation.py','nuc_registry_eval_backend_v3.py','nuc_registry_eval_broker.py','nuc_registry_eval_deadline.py','nuc_registry_eval_server_per_generation.py','nuc_registry_eval_client_per_generation.py','nuc_registry_eval_coordinator_per_generation.py','nuc_registry_evaluator.py','nuc_registry_eval_snapshot_provision.py','nuc_registry_eval_provenance.py','nuc_registry_transition_gate.py','nuc_registry_attestation_profiles.py'},'package unavailable')
 old.directory(PREFIX,0,2002,0o750)
 for filename,digest in pins.items():
  require(isinstance(filename,str) and __import__('re').fullmatch(r'[A-Za-z0-9_-]+\.py',filename) and isinstance(digest,str) and __import__('re').fullmatch(r'[0-9a-f]{64}',digest),'package pin unavailable')
  path=PREFIX/filename;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);old.noacl(fd);require((st.st_uid,st.st_gid,st.st_nlink,st.st_mode&0o7777)==(0,2002,1,0o440) and st.st_size<=1000000,'package file unavailable');data=os.read(fd,1000001);require(len(data)==st.st_size and sha(data)==digest,'package changed')
  finally:os.close(fd)
 name,socket,service=bodies(g);parent=RUN/'evaluator-production'/g;scopefile=PREFIX/(g+'.scope.json');marker=ROOT/(g+'.evaluator-service-started.json');done=ROOT/(g+'.evaluator-service-complete.json')
 require(not any(os.path.lexists(p) for p in (parent,scopefile,marker,done,UNIT/(name+'.service'),UNIT/(name+'.socket'))),'service occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','--system','unit-paths'],env=old.ENV,capture_output=True,timeout=5,check=True).stdout.decode().splitlines();require(paths and len(paths)<=64 and all(pathlib.Path(p).is_absolute() for p in paths),'unit paths unavailable')
 for suffix in ('.service','.socket'):
  unit=name+suffix;require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','unit occupied')
  for base in paths:
   for f in [unit,unit+'.d',suffix[1:]+'.d']+[name[:i+1]+suffix[1:]+'.d' for i,c in enumerate(name) if c=='-']:require(not os.path.lexists(pathlib.Path(base)/f),'unit path occupied')
 return {'generation':g,'registry_sha256':reg,'catalog_sha256':complete['catalog_sha256'],'package_sha256':sha(old.read(ROOT/'evaluator-package-v2.json',0o600)),'candidate_sha256':cat['snapshot_sha256'],'service_sha256':sha(service),'socket_sha256':sha(socket),'scope':'install only; no activation'}
def plan():
 with gate.admission():return _plan()
def apply(reviewed):
 with gate.admission():return _apply(reviewed)
def _apply(reviewed):
 require(_plan()==reviewed,'service plan changed');g=reviewed['generation'];name,socket,service=bodies(g);old.store(ROOT/(g+'.evaluator-service-started.json'),json.dumps(reviewed,sort_keys=True).encode()+b'\n',0o600)
 scope=json.dumps({'schema':1,'generation':g,'candidate_sha256':reviewed['candidate_sha256']},sort_keys=True,separators=(',',':')).encode();fd=os.open(PREFIX/(g+'.scope.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o440)
 try:
  os.fchown(fd,0,2002);os.fchmod(fd,0o440);view=memoryview(scope)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(PREFIX)
 parent=RUN/'evaluator-production'
 if not os.path.lexists(parent):os.mkdir(parent,0o711);os.chmod(parent,0o711);old.syncdir(RUN)
 old.directory(parent,0,0,0o711);child=parent/g;os.mkdir(child,0o710);os.chmod(child,0o710);os.chown(child,0,2002);old.syncdir(parent)
 old.store(UNIT/(name+'.socket'),socket,0o644);old.store(UNIT/(name+'.service'),service,0o644);old.ctl('daemon-reload')
 for suffix in ('.socket','.service'):
  n=name+suffix
  for k,v in (('LoadState','loaded'),('Names',n),('FragmentPath',str(UNIT/n)),('DropInPaths',''),('ActiveState','inactive'),('Job','')):require(old.ctl('show',n,'-p',k,'--value')==v,'unit identity unavailable')
 result={'generation':g,'installed':True,'started':False,'fixture_only':False};old.store(ROOT/(g+'.evaluator-service-complete.json'),json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
