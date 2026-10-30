"""Create-only native attestor probe; no grant request or journal mutation."""
import hashlib,json,os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
SOURCE=pathlib.Path('/tmp/sfactory-attestor-build-20261030/probe')
SHA='09a8bc07db0b5573cd4cce738dc41d593b01acdf5c4b328fd40a836896e7f8f6'
DEST=old.PREFIX/'root-attestor-probe'; START=old.ETC/'real-attestor-probe-started.json';DONE=old.ETC/'real-attestor-probe-complete.json'
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
 return {'source':source_info(),'attestation_sha256':ATTEST_SHA,'scope':'read-only attestation; no grant or journal request'}
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
 result=subprocess.run([str(DEST)],env=old.ENV,capture_output=True,timeout=50,check=False)
 require(result.returncode==0 and len(result.stdout)<=8192 and len(result.stderr)<=8192,'native attestor failed or unknown')
 value=json.loads(result.stdout);require(value=={'service_attested':True,'grant_requested':False},'attestor output mismatch')
 old.read(ATTEST,0o600,ATTEST_SHA)
 old.store(DONE,json.dumps({'probe_sha256':SHA,'attestation_sha256':ATTEST_SHA,'service_attested':True,'grant_requested':False},sort_keys=True).encode()+b'\n',0o600)
 return {'probe_sha256':SHA,'attestation_sha256':ATTEST_SHA,'service_attested':True,'grant_requested':False}
