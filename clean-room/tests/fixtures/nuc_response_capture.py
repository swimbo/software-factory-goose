"""Host-only capture of bounded provider response bodies for this run."""
import hashlib,json,os,stat
from nuc_stream_contract import RAW_SSE_BYTES
class ResponseCapture:
 def __init__(self,root):
  self.fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);st=os.fstat(self.fd)
  if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700:os.close(self.fd);raise RuntimeError('capture root unavailable')
  self.count=0
 def __call__(self,body):
  if not isinstance(body,bytes) or not 0<len(body)<=RAW_SSE_BYTES or self.count>=2:raise RuntimeError('capture unavailable')
  name='provider-body-'+str(self.count)+'.bin';digest=hashlib.sha256(body).hexdigest()
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
  with os.fdopen(fd,'wb') as output:output.write(body);output.flush();os.fsync(output.fileno())
  meta=os.open(name+'.sha256',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
  with os.fdopen(meta,'w') as output:output.write(digest+'\n');output.flush();os.fsync(output.fileno())
  os.fsync(self.fd);self.count+=1
 def close(self):os.close(self.fd)
