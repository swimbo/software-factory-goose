"""Create-only installation of reviewed registry grant candidates; never execute them."""
import hashlib,json,os,pathlib,stat
import nuc_grant_sidecar_install as old

SOURCE=pathlib.Path('/tmp/sfactory-registry-attestor.kuXuW0Pf/candidates')
START=old.ETC/'registry-grant-install-started.json'
DONE=old.ETC/'registry-grant-install-complete.json'
FILES={
 'registry-attestor-probe':'aa2868160da22acbdae103c118f952cc8d8675fe31b0558dec969c7f96b21642',
 'registry-grant-prepare':'73267031be1452b440df3ee53b8857e1a616809812515134a2c1ccf5394f26bd',
 'native-registry-readiness':'78d9260aa41730951dc2ae130d36b59c44fb64a0f817c6fb7133f2504544b195',
}
DEST=old.PREFIX
BOOT=pathlib.Path('/proc/sys/kernel/random/boot_id')

def require(ok,msg):
 if not ok:raise RuntimeError(msg)

def checked_source(name,digest,out=None):
 fd=os.open(SOURCE/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd)
  require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(1000,1000,1,0o700) and 0<st.st_size<=10_000_000,'candidate metadata mismatch')
  old.noacl(fd); h=hashlib.sha256(); total=0
  while True:
   part=os.read(fd,65536)
   if not part:break
   total+=len(part);require(total<=st.st_size,'candidate grew');h.update(part)
   if out is not None:
    view=memoryview(part)
    while view:
     n=os.write(out,view);require(n>0,'short write');view=view[n:]
  require(total==st.st_size and h.hexdigest()==digest,'candidate digest mismatch')
  return {'dev':st.st_dev,'ino':st.st_ino,'size':total,'sha256':digest}
 finally:os.close(fd)

def plan():
 require(os.geteuid()==0,'root required')
 for path in ('/','/tmp',str(SOURCE.parent),str(SOURCE)):
  # /tmp is deliberately sticky/shared; only the two private parents carry candidates.
  if path not in ('/','/tmp'):old.directory(pathlib.Path(path),1000,1000,0o700)
 old.directory(DEST,0,0,0o755);old.directory(old.ETC,0,0,0o711)
 require(not any(os.path.lexists(p) for p in (START,DONE)),'installation already attempted')
 require(not any(os.path.lexists(DEST/name) for name in FILES),'destination occupied')
 items={name:checked_source(name,digest) for name,digest in FILES.items()}
 return {'schema':1,'files':items,'boot_id':BOOT.read_text().strip(),'scope':'create only; no execution, grant request or activation'}

def apply(approved):
 require(plan()==approved,'installation plan changed')
 old.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 for name,digest in FILES.items():
  fd=os.open(DEST/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o755)
  try:
   observed=checked_source(name,digest,fd)
   require(observed==approved['files'][name],'candidate identity changed')
   os.fchmod(fd,0o755);os.fsync(fd)
  finally:os.close(fd)
  old.syncdir(DEST);old.read(DEST/name,0o755,digest,10_000_000)
 result={'schema':1,'boot_id':approved['boot_id'],'files':FILES,'executed':False,'grant_requested':False}
 old.store(DONE,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 return result
