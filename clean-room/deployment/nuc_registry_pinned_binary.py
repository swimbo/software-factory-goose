"""Bounded streaming verification of a fixed root-owned executable."""
import hashlib,os,stat
import nuc_grant_sidecar_install as old
MAX_BYTES=300_000_000
CHUNK=65536
def require(v,m):
 if not v:raise RuntimeError(m)
def verify(path,expected_sha256,max_bytes=MAX_BYTES):
 require(isinstance(expected_sha256,str) and len(expected_sha256)==64 and all(x in '0123456789abcdef' for x in expected_sha256) and type(max_bytes) is int and 0<max_bytes<=MAX_BYTES,'binary pin unavailable')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);require(stat.S_ISREG(a.st_mode) and (a.st_uid,a.st_gid,a.st_nlink,stat.S_IMODE(a.st_mode))==(0,0,1,0o755) and 0<a.st_size<=max_bytes,'binary metadata unavailable');old.noacl(fd)
  h=hashlib.sha256();total=0
  while True:
   data=os.read(fd,CHUNK)
   if not data:break
   total+=len(data);require(total<=a.st_size,'binary grew');h.update(data)
  b=os.fstat(fd);require((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and total==a.st_size and h.hexdigest()==expected_sha256,'binary changed')
  return {'dev':a.st_dev,'ino':a.st_ino,'size':total,'sha256':expected_sha256}
 finally:os.close(fd)

def validate_restate_command(original):
 import re
 require(original.get('ActiveState')=='active' and original.get('MainPID','').isdigit() and int(original['MainPID'])>1 and re.fullmatch('[0-9a-f]{32}',original.get('InvocationID','')),'Restate identity unavailable')
 expected='{ path=/usr/local/libexec/software-factory-goose/private-restate ; argv[]=/usr/local/libexec/software-factory-goose/private-restate --base-dir /var/lib/software-factory-goose/journal/restate --node-name sfgoose-private --bind-ip 127.0.0.1 --listen-mode tcp --use-random-ports false --no-logo ; ignore_errors=no ;'
 require(original.get('ExecStart','').startswith(expected) and original['ExecStart'].count('{ path=')==1,'Restate command changed')
