"""Fixed read-only Rust grant structural probe; never opens a socket or starts work."""
import errno,fcntl,hashlib,json,os,pathlib,stat,subprocess
G='01M65NEH5T767H8Q5X71TTFR5S';BOOT='98b86bb5-c04c-46f5-951d-22e497102f29'
SOURCE=pathlib.Path('/tmp/sfactory-stop-build-_10otcq2/install-candidate/sfactory_root_grant_diagnostic')
SHA='e9df0921e999c6d2abaf72591a7d0fa8bdfc5287a20971a76c92e93d0ebde177'
STATE=pathlib.Path('/var/lib/software-factory-goose/stop');CAT=pathlib.Path('/etc/software-factory-goose/launch-catalog')
RECEIPT=STATE/(G+'.rust-structural-probe.json')
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def noacl(fd,directory=False):
 for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(fd,name)
  except OSError as e:
   if e.errno==errno.ENODATA:continue
   raise RuntimeError('ACL unavailable') from None
  raise RuntimeError('ACL present')

def directory(path,uid=0,mode=None):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if s.st_uid!=uid or s.st_gid!=uid or s.st_mode&0o022 or (mode is not None and stat.S_IMODE(s.st_mode)!=mode):raise RuntimeError('directory unavailable')
  noacl(fd,True)
 finally:os.close(fd)

def read(path,uid,mode,sha=None,limit=16_000_000):
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or s.st_gid!=uid or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=mode or not 0<s.st_size<=limit:raise RuntimeError('file unavailable')
  noacl(fd);data=bytearray()
  while len(data)<=limit:
   b=os.read(fd,min(65536,limit+1-len(data)))
   if not b:break
   data.extend(b)
  if len(data)!=s.st_size or (sha is not None and hashlib.sha256(data).hexdigest()!=sha):raise RuntimeError('file identity changed')
  return bytes(data)
 finally:os.close(fd)

def build_plan(host):
 if os.geteuid()!=0 or pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=BOOT:raise RuntimeError('identity changed')
 for p in (STATE,CAT):
  for d in (p,*p.parents):directory(d)
 directory(SOURCE.parent,1000,0o700)
 if os.path.lexists(RECEIPT):raise RuntimeError('probe receipt already exists')
 binary=read(SOURCE,1000,0o700,SHA);grant=read(STATE/(G+'.grant-verified'),0,0o600,limit=16384);catalog=read(CAT/(G+'.json'),0,0o600,limit=16384);intent=read(STATE/(G+'.grant-request'),0,0o600,limit=1024)
 return {'component':'real-grant-rust-structural','source_sha256':host.source_digest,'generation':G,'boot_id':BOOT,'binary_sha256':SHA,'grant_record_sha256':hashlib.sha256(grant).hexdigest(),'catalog_sha256':hashlib.sha256(catalog).hexdigest(),'request_intent_sha256':hashlib.sha256(intent).hexdigest(),'scope':'read-only historical structural validation; no socket, engine or launch'},binary

def apply(host,reviewed):
 spec,binary=build_plan(host)
 if spec!=reviewed:raise RuntimeError('probe plan changed')
 fd=os.memfd_create('sfactory-root-grant-diagnostic',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
 try:
  view=memoryview(binary)
  while view:
   n=os.write(fd,view)
   if n<=0:raise RuntimeError('memfd short write')
   view=view[n:]
  os.fchmod(fd,0o500)
  fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
  p=subprocess.run(['/proc/self/fd/'+str(fd)],pass_fds=(fd,),env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C'},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,check=False)
  if p.returncode or len(p.stdout)>2048 or len(p.stderr)>2048:raise RuntimeError('structural probe unavailable')
  result=json.loads(p.stdout)
  if set(result)!={'generation','binding_sha256','historical_now_ms','socket_called','engine_called'} or result['generation']!=G or result['socket_called'] is not False or result['engine_called'] is not False or not isinstance(result['historical_now_ms'],int):raise RuntimeError('structural probe result invalid')
 finally:os.close(fd)
 fd=os.open(RECEIPT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  noacl(fd);raw=json.dumps({'plan':spec,'result':result},sort_keys=True,separators=(',',':')).encode();view=memoryview(raw)
  while view:
   n=os.write(fd,view)
   if n<=0:raise RuntimeError('receipt short write')
   view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 return {'generation':G,'historical_structural_match':True,'socket_called':False,'engine_called':False,'receipt':str(RECEIPT)}
