"""Create a separate protected CLI with fixed registry endpoint selection."""
import hashlib,json,os,pathlib,stat
import nuc_grant_sidecar_install as old
SOURCE=pathlib.Path('/tmp/sfactory-sfctl-profile-0spp7esk/sfctl-profile')
SHA='9fd28f105beee4a63d468e14e281f1bffac6a536a7b93a1d55bcebd0dd53d5f7'
DEST=old.PREFIX/'sfctl-registry';START=old.ETC/'sfctl-registry-install-started.json';DONE=old.ETC/'sfctl-registry-install-complete.json'

def checked(out=None):
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);old.noacl(fd)
  if not stat.S_ISREG(s.st_mode) or (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))!=(1000,1000,1,0o700) or not 0<s.st_size<50_000_000:raise RuntimeError('CLI source unavailable')
  digest=hashlib.sha256();size=0
  while True:
   data=os.read(fd,65536)
   if not data:break
   size+=len(data);digest.update(data)
   if out is not None:
    view=memoryview(data)
    while view:
     n=os.write(out,view)
     if n<=0:raise RuntimeError('short CLI write')
     view=view[n:]
  if size!=s.st_size or digest.hexdigest()!=SHA:raise RuntimeError('CLI source changed')
  return {'dev':s.st_dev,'ino':s.st_ino,'size':size,'sha256':SHA}
 finally:os.close(fd)

def plan():
 if os.geteuid()!=0:raise RuntimeError('root required')
 old.directory(SOURCE.parent,1000,1000,0o700);old.directory(old.PREFIX,0,0,0o755);old.directory(old.ETC,0,0,0o711)
 if any(os.path.lexists(p) for p in (DEST,START,DONE)):raise RuntimeError('CLI installation already attempted')
 return {'source':checked(),'destination':str(DEST),'preserve_existing_sfctl':True,'execution':False}

def apply(reviewed):
 if plan()!=reviewed:raise RuntimeError('reviewed CLI plan changed')
 old.store(START,json.dumps(reviewed,sort_keys=True).encode()+b'\n',0o600)
 fd=os.open(DEST,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o755)
 try:
  if checked(fd)!=reviewed['source']:raise RuntimeError('CLI identity changed')
  os.fchmod(fd,0o755);os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(old.PREFIX);old.read(DEST,0o755,SHA,50_000_000)
 result={'installed_sha256':SHA,'existing_cli_preserved':True,'executed':False};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
