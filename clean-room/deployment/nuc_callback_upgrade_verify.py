"""Native capability-zero verification of the upgraded root package."""
import hashlib,json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_relay_package_install as pkg
UNIT='sfactory-callback-upgrade-verify.service';START=old.ETC/'callback-upgrade-verify-started.json';DONE=old.ETC/'callback-upgrade-verify-complete.json'
HELPER='604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e';MODULE='e99c1f9580c473f9c91a3f31cb6445db98e6420d07d306088c05d3da9d6c0dcf'
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','SYSTEMD_IN_CHROOT':'0'}
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def program(boot):
 files=dict(pkg.PINS);files['nuc_relay_systemd.py']=MODULE
 return '''import errno,hashlib,json,os,pathlib,stat
boot=%r;expected=%r;want=%r
if os.geteuid()!=0 or os.getegid()!=0:raise RuntimeError('identity')
f=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
if any(int(f[k].strip(),16)!=0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) or f['NoNewPrivs'].strip()!='1':raise RuntimeError('capability profile')
def read(p,mode,limit):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))!=(0,0,1,mode) or not 0<s.st_size<=limit:raise RuntimeError('file metadata')
  try:os.getxattr(fd,'system.posix_acl_access');raise RuntimeError('ACL')
  except OSError as e:
   if e.errno!=errno.ENODATA:raise
  data=b''
  while len(data)<=limit:
   b=os.read(fd,min(65536,limit+1-len(data)))
   if not b:break
   data+=b
  if len(data)!=s.st_size:raise RuntimeError('file changed')
  return data
 finally:os.close(fd)
def sha(b):return hashlib.sha256(b).hexdigest()
r=pathlib.Path('/etc/software-factory-goose');base=pathlib.Path('/usr/local/libexec/software-factory-goose');raw=read(base/'root-launch-host.py',0o755,1000000)
if sha(raw)!=want:raise RuntimeError('helper mismatch')
hm=read(r/'root-launch-host.json',0o600,65536);pm=read(r/'relay-package.json',0o600,65536)
if json.loads(hm)!={'schema':1,'boot_id':boot,'helper_sha256':want} or json.loads(pm)!={'schema':1,'files':expected}:raise RuntimeError('manifest mismatch')
if pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=boot:raise RuntimeError('boot mismatch')
for name,digest in expected.items():
 if sha(read(base/'relay'/name,0o444,1000000))!=digest:raise RuntimeError('package mismatch')
s={'__name__':'native_verify'};exec(compile(raw,'<protected-helper>','exec'),s);s['modules']()
print(json.dumps({'files_verified':len(expected),'helper_sha256':want,'helper_manifest_sha256':sha(hm),'package_manifest_sha256':sha(pm),'all_caps_zero':True,'nnp':True,'grant_requested':False},sort_keys=True))
'''%(boot,files,HELPER)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE),'verification already attempted')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied')
 completed=json.loads(old.read(old.ETC/'callback-upgrade-complete.json',0o600));boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 require(completed['boot_id']==boot and completed['helper_sha256']==HELPER and completed['module_sha256']==MODULE,'upgrade receipt mismatch')
 code=program(boot)
 return {'boot_id':boot,'unit':UNIT,'program_sha256':hashlib.sha256(code.encode()).hexdigest(),'scope':'native root cap-zero read-only package verification'}
def apply(approved):
 require(plan()==approved,'verification plan changed');old.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 p=subprocess.run(['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=40s','/usr/bin/python3','-I','-B','-c',program(approved['boot_id'])],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=55,check=False)
 require(p.returncode==0 and len(p.stdout)<8192 and len(p.stderr)<8192,'native verification unknown')
 result=json.loads(p.stdout);require(result['files_verified']==13 and result['helper_sha256']==HELPER and result['all_caps_zero'] is True and result['nnp'] is True and result['grant_requested'] is False,'native verification mismatch')
 old.store(DONE,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return result
