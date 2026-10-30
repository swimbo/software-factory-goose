"""Create-only fixed grant preparation executable; do not execute it."""
import hashlib,json,os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
SOURCE=pathlib.Path('/tmp/sfactory-attestor-build-20261030/grant-prepare')
SHA='db7abd9cbd0aaf17a51b3b3a56848adc84475865d96200dbfa23f4ea8ef7ec02'
DEST=old.PREFIX/'sfactory-root-grant-prepare'; START=old.ETC/'root-grant-prepare-install-started.json';DONE=old.ETC/'root-grant-prepare-install-complete.json'
ATTEST=old.ETC/'real-process-attestation.json'; ATTEST_SHA='a25ff97dc1cc94f533ebb2aba00d3f08338532c275a025420c0715a532763c95'

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def source_info():
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_nlink,stat.S_IMODE(s.st_mode))==(1000,1,0o700) and s.st_size<10000000,'probe source mismatch')
  h=hashlib.sha256();total=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   total+=len(b);h.update(b)
  require(total==s.st_size and h.hexdigest()==SHA,'probe source digest mismatch');return {'dev':s.st_dev,'ino':s.st_ino,'size':total,'sha256':SHA}
 finally:os.close(fd)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (DEST,START,DONE)),'probe already attempted')
 old.directory(SOURCE.parent,1000,1000,0o700);old.directory(old.PREFIX,0,0,0o755);old.read(ATTEST,0o600,ATTEST_SHA)
 return {'source':source_info(),'attestation_sha256':ATTEST_SHA,'scope':'install only; do not execute or request a grant'}
def apply(approved):
 require(plan()==approved,'probe plan changed');old.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 source=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);dest=os.open(DEST,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o700)
 try:
  h=hashlib.sha256();total=0
  while True:
   b=os.read(source,65536)
   if not b:break
   h.update(b);total+=len(b);view=memoryview(b)
   while view:
    n=os.write(dest,view);require(n>0,'short write');view=view[n:]
  require(total==approved['source']['size'] and h.hexdigest()==SHA,'source changed');os.fchmod(dest,0o700);os.fsync(dest)
 finally:os.close(source);os.close(dest)
 old.syncdir(old.PREFIX)
 old.read(ATTEST,0o600,ATTEST_SHA)
 old.store(DONE,json.dumps({'binary_sha256':SHA,'attestation_sha256':ATTEST_SHA,'executed':False},sort_keys=True).encode()+b'\n',0o600)
 return {'binary_sha256':SHA,'attestation_sha256':ATTEST_SHA,'executed':False}
