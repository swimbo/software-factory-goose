#!/usr/local/bin/python3
"""Fixture-only fixed writer. Must run in the owned network-none executor."""
import json,os,sys,uuid
from nuc_file_contract import FILE_NAMES,MAX_FRAME_BYTES,canonical_arguments,strict_loads

REFUSED={'status':'refused','reason':'execution_unavailable'}

def execute(request,work='/work'):
 try:canonical_arguments(request)
 except (ValueError,TypeError,RecursionError):return {'status':'refused','reason':'invalid_request'}
 try:directory=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 except OSError:return dict(REFUSED)
 temporary=[];created=[];successful=False
 try:
  for name in FILE_NAMES:
   raw=request['files'][name].encode('utf-8')
   tmp='.factory-'+uuid.uuid4().hex
   fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644,dir_fd=directory);temporary.append(tmp)
   with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
   os.link(tmp,name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
   st=os.stat(tmp,dir_fd=directory,follow_symlinks=False);created.append((name,st.st_dev,st.st_ino))
  os.fsync(directory);successful=True
 except OSError:pass
 finally:
  if not successful:
   for name,dev,ino in reversed(created):
    try:
     st=os.stat(name,dir_fd=directory,follow_symlinks=False)
     if (st.st_dev,st.st_ino)==(dev,ino):os.unlink(name,dir_fd=directory)
    except OSError:pass
  for name in temporary:
   try:os.unlink(name,dir_fd=directory)
   except OSError:successful=False
  try:os.fsync(directory)
  except OSError:successful=False
  os.close(directory)
 if not successful:return dict(REFUSED)
 return {'status':'executed','exit_code':0,'stdout':'Both task files written.','stderr':''}

def main():
 if sys.argv!=[sys.argv[0],'--tool-request']:return 1
 try:result=execute(strict_loads(sys.stdin.buffer.read(MAX_FRAME_BYTES+1)))
 except (ValueError,UnicodeError,RecursionError):result={'status':'refused','reason':'invalid_request'}
 print(json.dumps(result,separators=(',',':')),flush=True);return 0

if __name__=='__main__':sys.exit(main())
