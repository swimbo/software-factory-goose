"""Fail-closed per-challenge broker core; no executable or deployment entrypoint.

A root-owned launcher must implement launch_and_reconcile with an independent
kernel deadline and exact-ID cleanup. This module never supplies Docker access to
the evaluator UID and does not claim that its backend has been deployed.
"""
import fcntl,hashlib,json,os,re,stat,threading
from nuc_registry_evaluator import CASES,FILES,GENERATION,MAX_OUTPUT
HEX=re.compile(r'[0-9a-f]{64}\Z')
class Unavailable(RuntimeError):pass

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()

def durable(dirfd,name,data):
 fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dirfd)
 try:
  os.fchmod(fd,0o600);v=memoryview(data)
  while v:
   n=os.write(fd,v)
   if n<=0:raise Unavailable('journal unavailable')
   v=v[n:]
  os.fsync(fd)
 finally:os.close(fd)
 os.fsync(dirfd)

class Broker:
 def __init__(self,dirfd,snapshot,backend,generation,no_acl):
  if not isinstance(generation,str) or re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',generation) is None:raise Unavailable('catalog unavailable')
  if not isinstance(snapshot,dict) or set(snapshot)!=set(FILES) or any(not isinstance(snapshot[k],str) or not HEX.fullmatch(snapshot[k]) for k in FILES) or not callable(getattr(backend,'launch_and_reconcile',None)):raise Unavailable('catalog unavailable')
  st=os.fstat(dirfd)
  if not stat.S_ISDIR(st.st_mode) or (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(0,0,0o700) or not callable(no_acl):raise Unavailable('journal unavailable')
  no_acl(dirfd,True)
  self.dirfd=dirfd;self.snapshot=dict(snapshot);self.backend=backend;self.generation=generation;self.no_acl=no_acl;self.lock=threading.Lock()
 def run(self,peer_uid,q):
  with self.lock:
   fcntl.flock(self.dirfd,fcntl.LOCK_EX)
   try:return self._run(peer_uid,q)
   finally:fcntl.flock(self.dirfd,fcntl.LOCK_UN)
 def _run(self,peer_uid,q):
  if peer_uid!=2002 or not isinstance(q,dict) or set(q)!={'schema','generation','sequence','kind','args','candidate_sha256'} or type(q['schema']) is not int or q['schema']!=1 or q['generation']!=self.generation or q['candidate_sha256']!=self.snapshot or type(q['sequence']) is not int or not 1<=q['sequence']<=22:raise Unavailable('request unavailable')
  seq=q['sequence'];expected_args=list(CASES[(seq-1)//3][0]) if seq<=21 else []
  if q['kind']!=('hello' if seq<=21 else 'unittest') or q['args']!=expected_args:raise Unavailable('challenge unavailable')
  # A surviving intent without the prior completed receipt is never retried.
  if seq>1:
   try:
    fd=os.open(f'{seq-1:02}.done',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=self.dirfd)
    try:
     st=os.fstat(fd)
     if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>4096:raise Unavailable('prior receipt unavailable')
     self.no_acl(fd,False);raw=os.read(fd,4097);previous=json.loads(raw)
    finally:os.close(fd)
    if previous.get('sequence')!=seq-1 or previous.get('generation')!=self.generation or previous.get('candidate_sha256')!=self.snapshot:raise Unavailable('prior receipt unavailable')
   except Exception:raise Unavailable('prior receipt unavailable') from None
  intent=canonical(q);digest=hashlib.sha256(intent).hexdigest()
  try:durable(self.dirfd,f'{seq:02}.intent',intent)
  except Exception:raise Unavailable('challenge unavailable') from None
  try:
   result=self.backend.launch_and_reconcile(q,digest)
   if not isinstance(result,dict) or set(result)!={'generation','sequence','intent_sha256','candidate_sha256','container_id','deadline_armed','kernel_empty','exact_id_removed','exit_code','stdout','stderr'} or result['generation']!=self.generation or result['sequence']!=seq or result['intent_sha256']!=digest or result['candidate_sha256']!=self.snapshot or not isinstance(result['container_id'],str) or not HEX.fullmatch(result['container_id']) or any(result[k] is not True for k in ('deadline_armed','kernel_empty','exact_id_removed')) or type(result['exit_code']) is not int or not isinstance(result['stdout'],bytes) or not isinstance(result['stderr'],bytes) or len(result['stdout'])>MAX_OUTPUT or len(result['stderr'])>MAX_OUTPUT:raise Unavailable('challenge outcome unknown')
   receipt={'schema':1,'generation':self.generation,'sequence':seq,'intent_sha256':digest,'candidate_sha256':self.snapshot,'container_id':result['container_id'],'stdout_sha256':hashlib.sha256(result['stdout']).hexdigest(),'stderr_sha256':hashlib.sha256(result['stderr']).hexdigest(),'exit_code':result['exit_code']}
   durable(self.dirfd,f'{seq:02}.done',canonical(receipt))
  except Exception:raise Unavailable('challenge outcome unknown') from None
  return {'schema':1,'generation':self.generation,'sequence':seq,'candidate_sha256':self.snapshot,'exit_code':result['exit_code'],'stdout':result['stdout'],'stderr':result['stderr'],'exact_cleanup':True}
