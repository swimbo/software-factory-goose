"""Install the fixed root capability-free registry readiness binary; do not run it."""
import hashlib,json,os,pathlib,stat
import nuc_grant_sidecar_install as old
SRC=pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX/stripped/native-registry-readiness-cap0');DST=old.PREFIX/'native-registry-readiness-cap0'
SHA='932d93b82b2dfdeca4d83bb2f1033d5e9ffdd34c3f6f7619c37ed8bad77e607b';START=old.ETC/'native-cap0-install-started.json';DONE=old.ETC/'native-cap0-install-complete.json'
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def info():
 fd=os.open(SRC,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(1000,1000,1,0o700) and 0<st.st_size<10_000_000,'source mismatch');old.noacl(fd);h=hashlib.sha256();size=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   h.update(b);size+=len(b)
  require(size==st.st_size and h.hexdigest()==SHA,'source changed');return {'dev':st.st_dev,'ino':st.st_ino,'size':size,'sha256':SHA}
 finally:os.close(fd)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (DST,START,DONE)),'destination occupied');old.directory(SRC.parent,1000,1000,0o700);old.directory(old.PREFIX,0,0,0o755)
 return {'source':info(),'scope':'install only; no readiness execution or grant'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 src=os.open(SRC,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);dst=os.open(DST,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o755)
 try:
  h=hashlib.sha256();total=0
  while True:
   b=os.read(src,65536)
   if not b:break
   total+=len(b);h.update(b);v=memoryview(b)
   while v:
    n=os.write(dst,v);require(n>0,'short write');v=v[n:]
  require(h.hexdigest()==SHA and total==approved['source']['size'],'source changed');os.fchmod(dst,0o755);os.fsync(dst)
 finally:os.close(src);os.close(dst)
 old.syncdir(old.PREFIX);old.read(DST,0o755,SHA,10_000_000);result={'installed':True,'executed':False,'sha256':SHA};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
