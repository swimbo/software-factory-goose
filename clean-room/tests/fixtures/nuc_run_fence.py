#!/usr/bin/env python3
"""Fresh run-only durable dispatch fence. Not a production budget authority."""
import fcntl,hashlib,json,os,pathlib,stat,uuid
from contextlib import contextmanager

class Denied(Exception):pass

def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()

class RunFence:
 def __init__(self,root,run,task,*,create=False):
  self.root=pathlib.Path(root);self.run=run;self.task=task
  if not all(isinstance(v,str) and 0<len(v)<=128 and all(c.isascii() and (c.isalnum() or c in '_-') for c in v) for v in (run,task)):raise Denied('scope unavailable')
  self.dirfd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  st=os.fstat(self.dirfd)
  if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700:
   os.close(self.dirfd);raise Denied('scope unavailable')
  with self.locked():
   if not self.exists('state'):
    if not create:raise Denied('state unavailable')
    try:marker=os.open('initialized',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.dirfd)
    except OSError:raise Denied('state unavailable') from None
    try:os.fsync(marker)
    finally:os.close(marker)
    os.fsync(self.dirfd)
    self.commit({'run':run,'task':task,'stage':'ready0'})
   self.read()
 def exists(self,name):
  try:os.stat(name,dir_fd=self.dirfd,follow_symlinks=False);return True
  except FileNotFoundError:return False
 @contextmanager
 def locked(self):
  fd=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=self.dirfd)
  try:
   st=os.fstat(fd)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1:raise Denied('lock unavailable')
   fcntl.flock(fd,fcntl.LOCK_EX);yield
  finally:os.close(fd)
 def read(self):
  fd=os.open('state',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.dirfd)
  try:
   st=os.fstat(fd)
   if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600 or not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>65536:raise Denied('state unavailable')
   with os.fdopen(fd) as f:fd=-1;state=json.load(f)
  except (ValueError,OSError):raise Denied('state unavailable') from None
  finally:
   if fd>=0:os.close(fd)
  if not isinstance(state,dict) or state.get('run')!=self.run or state.get('task')!=self.task:raise Denied('scope mismatch')
  return state
 def commit(self,state):
  name='tmp-'+uuid.uuid4().hex;fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.dirfd)
  try:
   with os.fdopen(fd,'w') as f:json.dump(state,f,sort_keys=True,separators=(',',':'));f.flush();os.fsync(f.fileno())
   os.replace(name,'state',src_dir_fd=self.dirfd,dst_dir_fd=self.dirfd);os.fsync(self.dirfd)
  finally:
   try:os.unlink(name,dir_fd=self.dirfd)
   except FileNotFoundError:pass
 def begin_inference(self,turn,request):
  if turn not in (0,1) or not isinstance(request,bytes) or not 0<len(request)<=65536:raise Denied('request unavailable')
  with self.locked():
   s=self.read()
   if s.get('stage')!=f'ready{turn}':raise Denied('dispatch unavailable')
   call=digest(canonical([self.run,self.task,turn,digest(request)]));s.update(stage=f'unknown{turn}',call=call,request=digest(request));self.commit(s);return call
 def record_tool(self,call,response,tool_id,arguments):
  if not isinstance(response,bytes) or not 0<len(response)<=1048576 or not isinstance(tool_id,str) or not 0<len(tool_id)<=128 or not isinstance(arguments,dict):raise Denied('response unavailable')
  with self.locked():
   s=self.read()
   if s.get('stage')!='unknown0' or s.get('call')!=call:raise Denied('dispatch unavailable')
   s.update(stage='tool_ready',response=digest(response),tool_id=tool_id,arguments=digest(canonical(arguments)));self.commit(s)
 def begin_tool(self,tool_id,arguments):
  with self.locked():
   s=self.read()
   if s.get('stage')!='tool_ready' or s.get('tool_id')!=tool_id or s.get('arguments')!=digest(canonical(arguments)):raise Denied('tool unavailable')
   s['stage']='tool_unknown';self.commit(s)
 def record_tool_result(self,tool_id,result):
  if not isinstance(result,bytes) or not 0<len(result)<=65536:raise Denied('result unavailable')
  with self.locked():
   s=self.read()
   if s.get('stage')!='tool_unknown' or s.get('tool_id')!=tool_id:raise Denied('tool unavailable')
   s.update(stage='ready1',tool_result=digest(result));self.commit(s)
 def record_final(self,call,response):
  if not isinstance(response,bytes) or not 0<len(response)<=1048576:raise Denied('response unavailable')
  with self.locked():
   s=self.read()
   if s.get('stage')!='unknown1' or s.get('call')!=call:raise Denied('dispatch unavailable')
   s.update(stage='done',final=digest(response));self.commit(s)
