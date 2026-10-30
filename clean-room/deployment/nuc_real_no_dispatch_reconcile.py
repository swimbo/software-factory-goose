"""Fixed retained-generation no-dispatch audit and callback stop. Review only.

No Docker command, launch, grant, account or shared-service mutation occurs.
The permanent reservation, frozen cgroup, failed launch unit and prior records
are preserved. The proof assumes the root/systemd manager and root-owned state
were not modified by an untrusted administrator during the same boot.
"""
import errno,hashlib,json,os,pathlib,re,stat,subprocess
G='01M65NEH5T767H8Q5X71TTFR5S';TASK='01M65NEH5TBPKNDW21TE6FR3XA';LOW=G.lower()
BOOT='98b86bb5-c04c-46f5-951d-22e497102f29';CG_DEV=29;CG_INO=7663196
ROOT=pathlib.Path('/etc/software-factory-goose');STATE=pathlib.Path('/var/lib/software-factory-goose/stop');SYSTEM=pathlib.Path('/etc/systemd/system');PREFIX=pathlib.Path('/usr/local/libexec/software-factory-goose')
CG=pathlib.Path('/sys/fs/cgroup')/('sfactory'+LOW+'.slice');DRIVER='sfactory-intloop-launch-'+LOW+'.service';SOCKET='sfactoryrelay'+LOW+'.socket';SOCKET_PATH=pathlib.Path('/run/software-factory-goose/relay')/G/'relay.sock'
BIN_SHA='2c6dad55387e3e2e33e12f8ea8677e2e8987925fe189a2c17dcb61d577691157';HELPER_SHA='3de11eef342e32c98c2d87659d647fc33547048b7ea80699e3bf117ec5d9a06d'
TRANSACTION_SOURCE_SHA='1a6c5efa7dcc122d8bd571747b95f3dbd3fa800dac32fe4ccf4f42aa62a1bdc1';WRAPPER_SOURCE_SHA='4fac6e45f3df691150c57a95d1440ae64ae839a11e19e771d1a223b025b24883'
CAT_SHA='6bfedbfbff2c426291d592d0978839fb97b9c4cbadad96ea4f1251863ddc49fa';CLOSED_SHA='268e16f4713957bbe2e058495483ab5b86fa64d9047a5cd1e3ef39e608b447aa';OBS_SHA='48ab3eca5715b1f23ecc6d01789fcb7a55b027bc0ab565ed4ddcbbc4c6ee94fb'
START_SHA='52b2e8c78cb936930fb7b809e773cc64d087e212d517b646ef18485c1daaa1b1';GRANT_SHA='0680dbd51240d7713d4e24f9c14b6c1065592b48f239bd095659d60f5684fefe';INVOCATION='b3f32903ff7e437c833993c95ce6622d'
PINS={'sfactoryrelay'+LOW+'.service':'53064c9207d120ca079eda04b4e58b7f2b777770379230154d8ac876e5d1c985','sfactoryrelay'+LOW+'.socket':'853de935b514ad03bdd96ff930cf88bafd1dd0e22ef12eedb5b6fb35f1cb843d','sfactorywriter'+LOW+'.service':'5c10bb037b979f9f4f47948d689bbba8929adf1043ae620bf469263cdbf8086f','sfactorywriter'+LOW+'.socket':'5bf190668ea243082365b86fd94ef107d23795956488cf989e59a06ca1de8bb5'}
SOURCE=pathlib.Path('/tmp/sfactory-stop-build-_10otcq2/crates/watchdog/src');INTENT=STATE/(G+'.no-dispatch-stop-intent.json');RECEIPT=STATE/(G+'.no-dispatch-receipt.json')
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0','LC_ALL':'C'}
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def noacl(fd,directory=False):
 for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(fd,name)
  except OSError as e:
   if e.errno==errno.ENODATA:continue
   raise RuntimeError('ACL unavailable') from None
  raise RuntimeError('ACL present')
def directory(path,uid=0,gid=0,mode=None):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if s.st_uid!=uid or s.st_gid!=gid or s.st_mode&0o022 or (mode is not None and stat.S_IMODE(s.st_mode)!=mode):raise RuntimeError('directory mismatch')
  noacl(fd,True)
 finally:os.close(fd)
def read(path,uid,mode,sha=None,limit=10_000_000):
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or s.st_gid!=uid or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=mode or s.st_size>limit:raise RuntimeError('file identity mismatch')
  noacl(fd);h=hashlib.sha256();buf=bytearray()
  while True:
   b=os.read(fd,65536)
   if not b:break
   buf.extend(b);h.update(b)
   if len(buf)>limit:raise RuntimeError('file oversized')
  if len(buf)!=s.st_size or (sha is not None and h.hexdigest()!=sha):raise RuntimeError('file digest mismatch')
  return bytes(buf)
 finally:os.close(fd)
def ctl(*args):
 p=subprocess.run(['/usr/bin/systemctl',*args],env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12,check=False)
 if p.returncode or len(p.stdout)>16384 or len(p.stderr)>8192:raise RuntimeError('manager unavailable')
 return p.stdout.decode().strip()
def prop(unit,key):return ctl('show',unit,'-p',key,'--value')
def original_fence():
 for suffix in ('lock','launch-consumed','create-intent','launch-seal','start-intent','deadline-intent.json','deadline-armed.json','host-create-intent.json','host-created.json','writer-create-intent.json','writer-created.json','goose-create-intent.json','goose-created.json','writer-start-intent.json','goose-start-intent.json','intloop-launch-complete.json'):
  if os.path.lexists(STATE/(G+'.'+suffix)):raise RuntimeError('dispatch state not absent')
 for suffix in ('scope.json','writer.json'):
  if os.path.lexists(ROOT/'relay-catalog'/(G+'.'+suffix)):raise RuntimeError('postclaim relay authority exists')

def driver():
 expected={'LoadState':'loaded','ActiveState':'failed','Result':'exit-code','ExecMainStatus':'1','MainPID':'0','ControlGroup':'','Job':'','Names':DRIVER,'Transient':'yes','FragmentPath':'/run/systemd/transient/'+DRIVER,'DropInPaths':'','InvocationID':INVOCATION,'User':'root','Group':'root','NoNewPrivileges':'yes','CapabilityBoundingSet':''}
 for k,v in expected.items():
  if prop(DRIVER,k)!=v:raise RuntimeError('driver terminal identity unavailable')
 cmd=prop(DRIVER,'ExecStart');prefix='{ path='+str(PREFIX/'root-launch')+' ; argv[]='+str(PREFIX/'root-launch')+' '+G+' ; ignore_errors=no ;'
 if not cmd.startswith(prefix) or cmd.count('{ path=')!=1:raise RuntimeError('driver command mismatch')
 cg=pathlib.Path('/sys/fs/cgroup/system.slice')/DRIVER
 if os.path.lexists(cg):
  s=os.lstat(cg)
  if not stat.S_ISDIR(s.st_mode) or (cg/'cgroup.events').read_text().splitlines().count('populated 0')!=1:raise RuntimeError('driver cgroup not empty')

def kernel():
 st=os.lstat(CG)
 if not stat.S_ISDIR(st.st_mode) or (st.st_dev,st.st_ino)!=(CG_DEV,CG_INO):raise RuntimeError('generation cgroup changed')
 fd=os.open(CG,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st2=os.fstat(fd)
  if (st2.st_dev,st2.st_ino)!=(CG_DEV,CG_INO):raise RuntimeError('cgroup descriptor changed')
  def control(name):
   f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
   try:return os.read(f,1025)
   finally:os.close(f)
  events=control('cgroup.events')
  if len(events)>1024 or b'populated 0' not in events.splitlines() or b'frozen 1' not in events.splitlines() or control('cgroup.freeze').strip()!=b'1':raise RuntimeError('generation not frozen empty')
 finally:os.close(fd)

def validate_units():
 manifest=json.loads(read(ROOT/'relay-catalog'/(G+'.units.json'),0,0o600,limit=65536))
 if manifest!={'schema':1,'generation':G,'units':PINS}:raise RuntimeError('unit manifest changed')
 for unit,sha in PINS.items():
  read(SYSTEM/unit,0,0o644,sha,65536)
  for key,value in [('LoadState','loaded'),('Names',unit),('FragmentPath',str(SYSTEM/unit)),('DropInPaths',''),('NeedDaemonReload','no'),('Job','')]:
   if prop(unit,key)!=value:raise RuntimeError('owned unit identity unavailable')
  state=prop(unit,'ActiveState')
  if unit==SOCKET:
   if state!='active':raise RuntimeError('callback socket not active')
  elif state not in ('inactive','failed'):raise RuntimeError('owned unit unexpectedly active')
  if unit.endswith('.service'):
   if prop(unit,'MainPID')!='0':raise RuntimeError('owned service still live')
   base='system.slice' if unit.startswith('sfactorywriter') else 'sfactory'+LOW+'.slice'
   path=pathlib.Path('/sys/fs/cgroup')/base/unit
   if os.path.lexists(path):
    s=os.lstat(path)
    if not stat.S_ISDIR(s.st_mode) or (path/'cgroup.events').read_text().splitlines().count('populated 0')!=1:raise RuntimeError('owned service cgroup not empty')
 if prop(SOCKET,'Listen')!=str(SOCKET_PATH)+' (Stream)' or prop(SOCKET,'SocketUser')!='root' or prop(SOCKET,'SocketGroup')!='sfgoose-worker' or prop(SOCKET,'SocketMode')!='0660' or prop(SOCKET,'FileDescriptorName')!='callback':raise RuntimeError('callback unit mismatch')
 directory(SOCKET_PATH.parent,2000,2000,0o700);s=os.lstat(SOCKET_PATH)
 if not stat.S_ISSOCK(s.st_mode) or s.st_uid!=0 or s.st_gid!=2001 or stat.S_IMODE(s.st_mode)!=0o660:raise RuntimeError('callback path mismatch')
 try:os.getxattr(SOCKET_PATH,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:
  if e.errno!=errno.ENODATA:raise RuntimeError('callback ACL unavailable') from None
 else:raise RuntimeError('callback ACL present')
 for name in ('sfactorydeadline'+LOW+'.timer','sfactorydeadline'+LOW+'.service'):
  if prop(name,'LoadState')!='not-found' or prop(name,'ActiveState')!='inactive' or prop(name,'Job')!='' or prop(name,'Names')!=name:raise RuntimeError('deadline manager state unresolved')

def make_plan(host):
 if os.geteuid()!=0 or pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=BOOT:raise RuntimeError('boot or caller mismatch')
 for base in (ROOT,STATE,SYSTEM,PREFIX):
  for p in (base,*base.parents):directory(p)
 if os.path.lexists(INTENT) or os.path.lexists(RECEIPT):raise RuntimeError('reconciliation already attempted')
 read(PREFIX/'root-launch',0,0o755,BIN_SHA);read(PREFIX/'root-launch-host.py',0,0o755,HELPER_SHA,1_000_000)
 read(SOURCE/'root_launch.rs',1000,0o644,TRANSACTION_SOURCE_SHA,1_000_000);read(SOURCE/'bin/sfactory_root_launch.rs',1000,0o644,WRAPPER_SOURCE_SHA,1_000_000)
 read(ROOT/'launch-catalog'/(G+'.json'),0,0o600,CAT_SHA,65536);read(STATE/(G+'.closed'),0,0o600,CLOSED_SHA,128);read(STATE/(G+'.observation'),0,0o600,OBS_SHA,65536);read(STATE/(G+'.intloop-launch-started.json'),0,0o600,START_SHA,65536);read(STATE/(G+'.grant-verified'),0,0o600,GRANT_SHA,16384)
 original_fence();driver();kernel();validate_units();original_fence()
 return {'component':'real-no-dispatch-reconcile','source_sha256':host.source_digest,'generation':G,'boot_id':BOOT,'invocation_id':INVOCATION,'launcher_sha256':BIN_SHA,'helper_sha256':HELPER_SHA,'transaction_source_sha256':TRANSACTION_SOURCE_SHA,'wrapper_source_sha256':WRAPPER_SOURCE_SHA,'catalog_sha256':CAT_SHA,'grant_record_sha256':GRANT_SHA,'closure_sha256':CLOSED_SHA,'observation_sha256':OBS_SHA,'cgroup_dev':CG_DEV,'cgroup_ino':CG_INO,'callback_unit':SOCKET,'scope':'same-boot source-ordering proof; stop only exact callback; retain frozen generation and reservation'}

def store(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  s=os.fstat(fd)
  if s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1:raise RuntimeError('record ownership mismatch')
  noacl(fd);raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();view=memoryview(raw)
  while view:
   n=os.write(fd,view)
   if n<=0:raise RuntimeError('record short write')
   view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)

def apply(host,reviewed):
 if make_plan(host)!=reviewed:raise RuntimeError('reviewed audit changed')
 store(INTENT,reviewed)
 # This is the exact preprovisioned callback socket only. Timeout is unknown.
 ctl('stop',SOCKET)
 if prop(SOCKET,'ActiveState')!='inactive' or prop(SOCKET,'Job')!='' or prop(SOCKET,'Names')!=SOCKET:raise RuntimeError('callback stop unresolved')
 driver();kernel();original_fence()
 store(RECEIPT,{'schema':1,'generation':G,'boot_id':BOOT,'driver_invocation':INVOCATION,'source_ordering_and_absent_lock_no_dispatch':True,'callback_stopped':True,'cgroup_retained_frozen_empty':True,'reservation_retained':True,'provider_outcome':'not_established','trust':'same boot, trusted root and systemd; protected launch state not deleted','source_sha256':host.source_digest})
 return {'generation':G,'no_dispatch_by_source_ordering':True,'callback_stopped':True,'cgroup_retained_frozen_empty':True,'reservation_retained':True,'provider_outcome':'not_established'}
