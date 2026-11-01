"""Bounded read-only sizing of fixed Restate data, prior to retirement."""
import os,stat
import nuc_restate_backup_tree as tree
import nuc_grant_sidecar_install as old
RESERVE=2*1024**3
def require(v,m):
 if not v:raise RuntimeError(m)
def inspect(source,destination_parent):
 old.directory(source.parent,2004,2004,0o700)
 fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);nodes=0;size=0
 try:
  root=os.fstat(fd);require(stat.S_ISDIR(root.st_mode) and (root.st_uid,root.st_gid,stat.S_IMODE(root.st_mode))==(2004,2004,0o755),'Restate source unavailable');tree.no_acl(fd,True)
  def walk(d,depth):
   nonlocal nodes,size
   require(depth<128,'source depth exceeded');before=os.fstat(d);names=[]
   with os.scandir(d) as entries:
    for entry in entries:names.append(entry.name);require(len(names)+nodes<=tree.MAX_FILES,'source entry bound exceeded')
   for name in names:
    nodes+=1;require(nodes<=tree.MAX_FILES and name not in ('.','..') and '/' not in name and '\x00' not in name,'source entry unavailable')
    st=os.stat(name,dir_fd=d,follow_symlinks=False);require(st.st_dev==root.st_dev and (st.st_uid,st.st_gid)==(2004,2004),'source owner or filesystem changed')
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
    if stat.S_ISDIR(st.st_mode):
     child=os.open(name,flags|os.O_DIRECTORY,dir_fd=d)
     try:require(tree.identity(os.fstat(child))==tree.identity(st),'source changed');tree.no_acl(child,True);walk(child,depth+1)
     finally:os.close(child)
    elif stat.S_ISREG(st.st_mode):
     require(st.st_nlink==1 and st.st_size>=0,'source file unavailable');size+=st.st_size;require(size<=tree.MAX_BYTES,'source byte bound exceeded');child=os.open(name,flags,dir_fd=d)
     try:require(tree.identity(os.fstat(child))==tree.identity(st),'source changed');tree.no_acl(child,False)
     finally:os.close(child)
    else:raise RuntimeError('unsupported source file')
   require(tree.identity(os.fstat(d))==tree.identity(before),'source directory changed')
  walk(fd,0);dest=os.open(destination_parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   d=os.fstat(dest);require(stat.S_ISDIR(d.st_mode) and (d.st_uid,d.st_gid,stat.S_IMODE(d.st_mode))==(0,0,0o711),'backup destination unavailable');old.noacl(dest,True);fs=os.fstatvfs(dest);free=fs.f_bavail*fs.f_frsize
  finally:os.close(dest)
  required=4*size+RESERVE;require(free>=required,'insufficient backup/restore capacity')
  return {'source_dev':root.st_dev,'source_ino':root.st_ino,'destination_dev':d.st_dev,'destination_ino':d.st_ino,'entries':nodes,'logical_bytes':size,'free_bytes_floor_gib':free//(1024**3),'required_bytes':required,'reserve_bytes':RESERVE,'snapshot_is_live':True}
 finally:os.close(fd)
