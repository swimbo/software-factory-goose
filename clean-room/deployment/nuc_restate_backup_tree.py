"""Bounded descriptor-anchored offline tree copy; caller proves stop and ownership.

No filesystem path is selected by an untrusted caller. This primitive does not
stop a process, authorize a transition, or prove that a backup is restorable.
"""
import errno,hashlib,json,os,stat

MAX_FILES=100000
MAX_BYTES=64*1024**3
MAX_MANIFEST_BYTES=16*1024**2
CHUNK=1024*1024

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def no_acl(fd,directory):
 for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(fd,name)
  except OSError as exc:require(exc.errno==errno.ENODATA,'ACL state unavailable')
  else:raise RuntimeError('ACL present')
def identity(s):
 return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def copy_tree(source_fd,destination_fd,uid,gid):
 """Copy into a new empty owned directory; return deterministic content manifest."""
 with os.scandir(destination_fd) as it:require(next(it,None) is None,'destination must be empty')
 src=os.fstat(source_fd);dst=os.fstat(destination_fd)
 require(stat.S_ISDIR(src.st_mode) and stat.S_ISDIR(dst.st_mode) and src.st_uid==uid and src.st_gid==gid and dst.st_uid==uid and dst.st_gid==gid,'tree owner mismatch')
 no_acl(source_fd,True);no_acl(destination_fd,True)
 entries=[];count=0;size=0;nodes=0;path_bytes=0
 def walk(sfd,dfd,prefix):
  nonlocal count,size,nodes,path_bytes
  original=os.fstat(sfd);names=[]
  with os.scandir(sfd) as it:
   for item in it:
    names.append(item.name);require(len(names)+nodes<=MAX_FILES,'tree entry bound exceeded')
  for name in sorted(names):
   require(name not in ('.','..') and '/' not in name and '\x00' not in name,'unsafe filename')
   nodes+=1;require(nodes<=MAX_FILES,'tree entry bound exceeded')
   path=prefix+'/'+name if prefix else name;require(path.count('/')<128,'tree depth exceeded');path_bytes+=len(os.fsencode(path));require(path_bytes+nodes*256<=MAX_MANIFEST_BYTES,'manifest bound exceeded')
   st=os.stat(name,dir_fd=sfd,follow_symlinks=False);require(st.st_dev==src.st_dev,'source filesystem boundary crossed');require(st.st_uid==uid and st.st_gid==gid,'source owner mismatch')
   flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK
   if stat.S_ISDIR(st.st_mode):
    child=os.open(name,flags|os.O_DIRECTORY,dir_fd=sfd)
    try:
     require(identity(os.fstat(child))==identity(st),'source directory changed');no_acl(child,True)
     os.mkdir(name,0o700,dir_fd=dfd);out=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=dfd)
     try:
      walk(child,out,path);os.fchmod(out,stat.S_IMODE(st.st_mode));os.utime(out,ns=(st.st_atime_ns,st.st_mtime_ns));os.fchown(out,uid,gid);os.fsync(out)
     finally:os.close(out)
    finally:os.close(child)
    entries.append({'path':path,'type':'directory','mode':stat.S_IMODE(st.st_mode),'mtime_ns':st.st_mtime_ns})
   elif stat.S_ISREG(st.st_mode):
    count+=1;size+=st.st_size;require(st.st_nlink==1 and st.st_size>=0 and count<=MAX_FILES and size<=MAX_BYTES,'file bound or link invalid')
    child=os.open(name,flags,dir_fd=sfd)
    try:
     require(identity(os.fstat(child))==identity(st),'source file changed');no_acl(child,False)
     out=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600,dir_fd=dfd)
     try:
      h=hashlib.sha256();total=0
      while True:
       chunk=os.read(child,CHUNK)
       if not chunk:break
       total+=len(chunk);require(total<=st.st_size,'source file grew');h.update(chunk);view=memoryview(chunk)
       while view:
        n=os.write(out,view);require(n>0,'short write');view=view[n:]
      require(total==st.st_size and identity(os.fstat(child))==identity(st),'source file changed')
      os.fsync(out);os.lseek(out,0,os.SEEK_SET);verify=hashlib.sha256();verified=0
      while True:
       chunk=os.read(out,CHUNK)
       if not chunk:break
       verified+=len(chunk);require(verified<=total,'destination verification failed');verify.update(chunk)
      require(verified==total and verify.digest()==h.digest(),'destination verification failed')
      os.fchmod(out,stat.S_IMODE(st.st_mode));os.utime(out,ns=(st.st_atime_ns,st.st_mtime_ns));os.fchown(out,uid,gid);os.fsync(out)
     finally:os.close(out)
    finally:os.close(child)
    entries.append({'path':path,'type':'file','mode':stat.S_IMODE(st.st_mode),'size':st.st_size,'mtime_ns':st.st_mtime_ns,'sha256':h.hexdigest()})
   else:raise RuntimeError('unsupported source file type')
   os.fsync(dfd)
  require(identity(os.fstat(sfd))==identity(original),'source directory changed')
 walk(source_fd,destination_fd,'');os.fsync(destination_fd)
 manifest={'schema':1,'files':count,'bytes':size,'entries':sorted(entries,key=lambda e:e['path'])}
 require(len(json.dumps(manifest,sort_keys=True,separators=(',',':'),allow_nan=False).encode())+1<=MAX_MANIFEST_BYTES,'manifest bound exceeded')
 return manifest
