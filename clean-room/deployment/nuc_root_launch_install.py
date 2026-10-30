"""Create-only fixed root-launch installer. No grant, engine or service effects."""
import errno,hashlib,json,os,pathlib,pwd,grp,stat,subprocess
ETC=pathlib.Path('/etc/software-factory-goose');STATE=pathlib.Path('/var/lib/software-factory-goose/stop');PREFIX=pathlib.Path('/usr/local/libexec/software-factory-goose');PKG=PREFIX/'relay'
SOURCE_HELPER=pathlib.Path('/tmp/sfactory-root-launch-stage-Zg8fNk2r/root-launch-host.py')
SOURCE_GRANT=pathlib.Path('/tmp/sfactory-stop-build-_10otcq2/install-candidate/sfactory_root_grant_prepare_v3')
SOURCE_LAUNCH=pathlib.Path('/tmp/sfactory-stop-build-_10otcq2/install-candidate/sfactory_root_launch_v3')
HELPER_SHA='3de11eef342e32c98c2d87659d647fc33547048b7ea80699e3bf117ec5d9a06d'
GRANT_SHA='4905a5bfda3ca5f62ba6ffc9e997961a64e2066baafee7b7bd28ccb4b2052af7'
LAUNCH_SHA='2c6dad55387e3e2e33e12f8ea8677e2e8987925fe189a2c17dcb61d577691157'
PROBE_SHA='09a8bc07db0b5573cd4cce738dc41d593b01acdf5c4b328fd40a836896e7f8f6'
ATTEST_SHA='a25ff97dc1cc94f533ebb2aba00d3f08338532c275a025420c0715a532763c95'
INTENT=STATE/'root-launch-install-intent.json';RECEIPT=STATE/'root-launch-install-receipt.json'
TARGETS=[PREFIX/'root-launch-host.py',PREFIX/'root-grant-prepare',PREFIX/'root-launch',ETC/'root-launch-host.json']
PINS={'nuc_relay_authority.py': 'dc336c313e3dbdbee0a84e1adf764895a8487657129dd6ca7cbc562ae59e3032', 'nuc_relay_core.py': 'f49f23d99cb4f03fa4dd61af7f7eda8df35d7411cf1d6289715a52871cf513b4', 'nuc_relay_stream.py': '524bb2f1437af3251ffc1e8fbc5f9c8357eaa40bea242cde0086791d17701d55', 'nuc_relay_systemd.py': 'ea16c500e2f2f7786210801d22802be6e8736217e39933133da466e3a1312031', 'nuc_relay_provider.py': '7d8904f2fb88be13894497ccbca928f9e1acf7a3169ddfb49d231d4770bd5c7a', 'nuc_relay_server.py': 'af18c8022820f29b42fe7d3ca880f4a489de67ed866e3b8abaaeb1558ef47213', 'nuc_relay_guard.py': '9da14d3fd079203d5b78956955da973c82548e3cf29fd6409db4599f27711efe', 'nuc_relay_writer.py': '6c89cd37dd45c08b1ec9652c7bdca8fce3dc5cde57af95100a590d9fa431b5ea', 'nuc_root_writer_broker.py': 'f8620c398a1181b6ec8131e726b1c27bf6ef74e4b2ee0e89fc6228c1dd5bf759', 'nuc_root_writer_service.py': '4defa9d5566a8bcf987b17c9a5c910064a525b131618a4c37bdb26e9308eda39', 'nuc_writer_binding.py': '2f415a1eceb1627dd3ca8548d146f5c1ba0135c5564d14f497b2299a0204411e', 'nuc_root_deadline_arm.py': '195e385703e433eaafb2e30e36a4de08a3ef01f084b175f944b276643c1534f4', 'nuc_root_grant_deadline.py': 'd29a4ffab144ddc17afd4142d8cd965d1f325b61a6072895b49d40be66cc0fd7'}
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0','LC_ALL':'C'}
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def no_acl(fd,directory=False):
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
  if s.st_uid!=uid or s.st_gid!=gid or s.st_mode&0o022 or (mode is not None and stat.S_IMODE(s.st_mode)!=mode):raise RuntimeError('directory identity mismatch')
  no_acl(fd,True)
 finally:os.close(fd)

def read(path,uid,mode,sha=None,maxsize=100_000_000):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or s.st_gid!=uid or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=mode or not 0<s.st_size<=maxsize:raise RuntimeError('file identity mismatch')
  no_acl(fd);chunks=[];total=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   total+=len(b)
   if total>maxsize:raise RuntimeError('file oversized')
   chunks.append(b)
  data=b''.join(chunks)
  if len(data)!=s.st_size or (sha is not None and hashlib.sha256(data).hexdigest()!=sha):raise RuntimeError('file digest mismatch')
  return data
 finally:os.close(fd)

def check_package():
 directory(PKG,mode=0o755)
 raw=read(ETC/'relay-package.json',0,0o600,maxsize=65536);m=json.loads(raw)
 if m!={'schema':1,'files':PINS}:raise RuntimeError('package manifest mismatch')
 if {p.name for p in PKG.iterdir()}!=set(PINS):raise RuntimeError('package entry mismatch')
 for name,sha in PINS.items():read(PKG/name,0,0o444,sha,1_000_000)
 return hashlib.sha256(raw).hexdigest()

def probe():
 binary=PREFIX/'root-attestor-probe';read(binary,0,0o700,PROBE_SHA,10_000_000)
 read(ETC/'real-process-attestation.json',0,0o600,ATTEST_SHA,16384)
 p=subprocess.run([str(binary)],env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
 if p.returncode or len(p.stdout)>8192 or len(p.stderr)>8192 or json.loads(p.stdout)!={'service_attested':True,'grant_requested':False}:raise RuntimeError('real sidecar attestation unavailable')
 return ATTEST_SHA

def build_plan(host):
 if os.geteuid()!=0:raise RuntimeError('root required')
 for p in (pathlib.Path('/'),pathlib.Path('/etc'),ETC,pathlib.Path('/var'),pathlib.Path('/var/lib'),STATE.parent,STATE,pathlib.Path('/usr'),pathlib.Path('/usr/local'),pathlib.Path('/usr/local/libexec'),PREFIX):directory(p)
 directory(STATE,mode=0o700);directory(SOURCE_HELPER.parent,1000,1000,0o700);directory(SOURCE_GRANT.parent,1000,1000,0o700)
 for name,uid in [('sfgoose-control',2000),('sfgoose-worker',2001),('sfgoose-eval',2002),('sfgoose-brake',2003),('sfgoose-journal',2004)]:
  u=pwd.getpwnam(name);gr=grp.getgrnam(name)
  if u.pw_uid!=uid or u.pw_gid!=uid or gr.gr_gid!=uid:raise RuntimeError('role identity mismatch')
 if any(os.path.lexists(p) for p in (*TARGETS,INTENT,RECEIPT)):raise RuntimeError('target or prior installation exists')
 helper=read(SOURCE_HELPER,1000,0o600,HELPER_SHA,1_000_000);grant=read(SOURCE_GRANT,1000,0o700,GRANT_SHA);launch=read(SOURCE_LAUNCH,1000,0o700,LAUNCH_SHA)
 package_sha=check_package();attest_sha=probe();boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 return {'component':'root-launch-install','source_sha256':host.source_digest,'boot_id':boot,'helper_sha256':HELPER_SHA,'grant_prepare_sha256':GRANT_SHA,'launch_sha256':LAUNCH_SHA,'package_manifest_sha256':package_sha,'real_attestation_sha256':attest_sha,'targets':[str(x) for x in TARGETS],'activation':False,'grant_requested':False,'engine_effects':False},(helper,grant,launch)

def syncdir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)
def create(path,data,mode):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 try:
  os.fchmod(fd,mode);st=os.fstat(fd)
  if st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1:raise RuntimeError('created owner mismatch')
  no_acl(fd);view=memoryview(data)
  while view:
   n=os.write(fd,view)
   if n<=0:raise RuntimeError('short write')
   view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 syncdir(path.parent)

def apply(host,reviewed):
 current,blobs=build_plan(host)
 if current!=reviewed:raise RuntimeError('reviewed installation changed')
 create(INTENT,json.dumps(reviewed,sort_keys=True,separators=(',',':')).encode(),0o600)
 for path,data in zip(TARGETS[:3],blobs):create(path,data,0o755)
 manifest={'schema':1,'boot_id':current['boot_id'],'helper_sha256':HELPER_SHA}
 create(TARGETS[3],json.dumps(manifest,sort_keys=True,separators=(',',':')).encode(),0o600)
 for path,sha in zip(TARGETS[:3],(HELPER_SHA,GRANT_SHA,LAUNCH_SHA)):read(path,0,0o755,sha)
 create(RECEIPT,json.dumps({'status':'installed_not_activated','source_sha256':host.source_digest,'boot_id':current['boot_id'],'helper_sha256':HELPER_SHA,'grant_prepare_sha256':GRANT_SHA,'launch_sha256':LAUNCH_SHA},sort_keys=True,separators=(',',':')).encode(),0o600)
 return {'status':'installed_not_activated','grant_requested':False,'engine_effects':False}
