"""Create-only pinned Python worker/writer images and protected Goose binary."""
import hashlib,io,json,os,pathlib,stat,subprocess,tarfile
ETC=pathlib.Path('/etc/software-factory-goose');STATE=pathlib.Path('/var/lib/software-factory-goose')
BUILD=STATE/'worker-image-build';RECEIPT=ETC/'worker-images.json'
SOURCE=pathlib.Path('/tmp/sfactory-worker-images-source')
BASE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
GOOSE_SOURCE=pathlib.Path('/tmp/sfactory-goose-protected-c0tz3oa4/goose-canary')
GOOSE_SHA='802d1478e6a53ef7c68a56ccfed3aec59eab0afd68aa411ec0c1b516dc5334db'
GOOSE_DEST=pathlib.Path('/usr/local/libexec/software-factory-goose/goose-protected-802d1478')
PINS={'nuc_goose_worker.py': 'c0f51ee7767c6448c1fa3908e137c280753de302af9e7196751bb67fbc601df1', 'nuc_fixed_writer.py': '4ade60e556a391795b8f2b13a5e6d52efb68a04d6d806f5e0bf76e3cdc0d3d8c', 'nuc_relay_authority.py': '74d22f187d0ebb3bf9c459b7ec3b5a37a8ecda2e1b7682043b04237cda030173'}
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','DOCKER_BUILDKIT':'0'}
D=['/usr/bin/docker','--host','unix:///run/docker.sock']
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def noacl(fd,directory=False):
 import errno
 for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(fd,name)
  except OSError as exc:
   if exc.errno==errno.ENODATA:continue
   raise RuntimeError('ACL unavailable') from None
  raise RuntimeError('ACL forbidden')

def directory(path,uid=0,mode=None):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd)
  if st.st_uid!=uid or st.st_mode&0o022 or mode is not None and stat.S_IMODE(st.st_mode)!=mode:raise RuntimeError('directory unavailable')
  noacl(fd,True)
 finally:os.close(fd)

def read_source(path,sha,maximum=65536):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);noacl(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=1000 or st.st_nlink!=1 or not 0<st.st_size<=maximum or st.st_mode&0o022:raise RuntimeError('source unavailable')
  data=bytearray()
  while len(data)<=maximum:
   chunk=os.read(fd,min(65536,maximum+1-len(data)))
   if not chunk:break
   data.extend(chunk)
  if len(data)!=st.st_size or hashlib.sha256(data).hexdigest()!=sha:raise RuntimeError('source changed')
  return bytes(data)
 finally:os.close(fd)

def stream_goose(destination=None):
 fd=os.open(GOOSE_SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);out=None
 try:
  st=os.fstat(fd);noacl(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=1000 or st.st_nlink!=1 or not 0<st.st_size<=400_000_000 or st.st_mode&0o022:raise RuntimeError('Goose source unavailable')
  if destination is not None:out=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o755)
  count=0;sha=hashlib.sha256()
  while True:
   raw=os.read(fd,65536)
   if not raw:break
   count+=len(raw);sha.update(raw)
   if count>st.st_size:raise RuntimeError('Goose source grew')
   if out is not None:
    view=memoryview(raw)
    while view:
     n=os.write(out,view)
     if n<=0:raise RuntimeError('short Goose copy')
     view=view[n:]
  if count!=st.st_size or sha.hexdigest()!=GOOSE_SHA:raise RuntimeError('Goose source changed')
  if out is not None:os.fchmod(out,0o755);os.fsync(out)
 finally:
  if out is not None:os.close(out)
  os.close(fd)
 if destination is not None:sync(destination.parent)

def docker(*args,body=None,timeout=30):
 r=subprocess.run([*D,*args],input=body,capture_output=True,env=ENV,timeout=timeout)
 if len(r.stdout)>65536 or len(r.stderr)>8192 or r.returncode!=0:raise RuntimeError('image operation failed or unknown')
 return r.stdout.decode()

def make_plan(host):
 if os.geteuid()!=0:raise RuntimeError('root required')
 for path in (ETC,STATE,GOOSE_DEST.parent):directory(path)
 directory(SOURCE,1000,0o700);directory(GOOSE_SOURCE.parent,1000,0o700)
 if any(os.path.lexists(p) for p in (BUILD,RECEIPT,GOOSE_DEST)):raise RuntimeError('prior image install exists')
 for name,sha in PINS.items():read_source(SOURCE/name,sha)
 stream_goose()
 if docker('image','inspect','--format','{{.Id}}',BASE).strip()!=BASE:raise RuntimeError('base image unavailable')
 return {'component':'worker-images','source_sha256':host.source_digest,'base_image':BASE,'files':PINS,'goose_sha256':GOOSE_SHA,'no_run_instructions':True,'start_services':False}

def sync(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def create(path,data,mode=0o600):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 try:
  os.fchmod(fd,mode);view=memoryview(data)
  while view:
   n=os.write(fd,view)
   if n<=0:raise RuntimeError('short write')
   view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 sync(path.parent)

def image(kind,names,program):
 dockerfile='FROM '+BASE+'\n'
 files={name:read_source(SOURCE/name,PINS[name]) for name in names}
 for name in names:dockerfile+='COPY '+name+' /factory/'+name+'\n'
 dockerfile+='ENTRYPOINT ["/usr/local/bin/python3","-I","-B","/factory/'+program+'"]\n'
 files['Dockerfile']=dockerfile.encode();data=io.BytesIO()
 with tarfile.open(fileobj=data,mode='w') as archive:
  for name,raw in files.items():
   info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o444;info.uid=info.gid=0;info.mtime=0;archive.addfile(info,io.BytesIO(raw))
 create(BUILD/(kind+'-create-intent.json'),json.dumps({'files':{n:hashlib.sha256(b).hexdigest() for n,b in files.items()}},sort_keys=True).encode())
 iidfile=BUILD/(kind+'-image-id')
 output=docker('build','--network=none','--pull=false','--iidfile',str(iidfile),'-',body=data.getvalue(),timeout=90)
 create(BUILD/(kind+'-build.log'),output.encode())
 fd=os.open(iidfile,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or s.st_size>128:raise RuntimeError('image ID unavailable')
  iid=os.read(fd,129).decode().strip()
 finally:os.close(fd)
 import re
 if not re.fullmatch(r'sha256:[0-9a-f]{64}',iid):raise RuntimeError('image ID unavailable')
 meta=json.loads(docker('image','inspect','--format','{{json .}}',iid))
 if meta['Id']!=iid or meta['Config']['Entrypoint']!=['/usr/local/bin/python3','-I','-B','/factory/'+program]:raise RuntimeError('image identity mismatch')
 return {'image_id':iid,'program_sha256':PINS[program],'files_sha256':{n:PINS[n] for n in names}}

def apply(host,reviewed):
 if make_plan(host)!=reviewed:raise RuntimeError('reviewed image plan changed')
 os.mkdir(BUILD,0o700);sync(STATE);create(BUILD/'intent.json',json.dumps(reviewed,sort_keys=True).encode())
 stream_goose(GOOSE_DEST)
 worker=image('worker',['nuc_goose_worker.py'],'nuc_goose_worker.py')
 create(BUILD/'worker-complete.json',json.dumps(worker,sort_keys=True).encode())
 writer=image('writer',['nuc_fixed_writer.py','nuc_relay_authority.py'],'nuc_fixed_writer.py')
 result={'schema':1,'purpose':'nuc-goose-write-files-images-v1','base_image_id':BASE,'goose_sha256':GOOSE_SHA,'worker':worker,'writer':writer,'engine_started':False}
 create(RECEIPT,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n')
 return result
