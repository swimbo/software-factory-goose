"""Bounded aggregate metadata inventory of live fixed Restate tree; no names or contents."""
import collections,errno,os,stat
import nuc_grant_sidecar_install as old
SOURCE='/var/lib/software-factory-goose/journal/restate'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0,'root required');root=os.open(SOURCE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);counts=collections.Counter();nodes=0;acl=0;other_dev=0
 try:
  rootst=os.fstat(root)
  def walk(fd,depth):
   nonlocal nodes,acl,other_dev
   require(depth<128,'depth exceeded');before=os.fstat(fd)
   names=[]
   with os.scandir(fd) as entries:
    for entry in entries:
     names.append(entry.name);require(len(names)+nodes<=100000,'entry limit')
   for name in names:
    nodes+=1;require(nodes<=100000 and name not in ('.','..') and '/' not in name,'entry invalid');st=os.stat(name,dir_fd=fd,follow_symlinks=False)
    kind='dir' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'other';counts[(kind,st.st_uid,st.st_gid,oct(stat.S_IMODE(st.st_mode)),st.st_nlink if kind=='file' else None)]+=1
    if st.st_dev!=rootst.st_dev:other_dev+=1;continue
    if kind in ('dir','file'):
     flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC|(os.O_DIRECTORY if kind=='dir' else 0);child=os.open(name,flags,dir_fd=fd)
     try:
      after=os.fstat(child);require((st.st_dev,st.st_ino)==(after.st_dev,after.st_ino),'entry changed')
      for attr in (('system.posix_acl_access','system.posix_acl_default') if kind=='dir' else ('system.posix_acl_access',)):
       try:os.getxattr(child,attr)
       except OSError as e:require(e.errno==errno.ENODATA,'ACL unavailable')
       else:acl+=1
      if kind=='dir':walk(child,depth+1)
     finally:os.close(child)
   require((before.st_dev,before.st_ino)==(os.fstat(fd).st_dev,os.fstat(fd).st_ino),'directory changed')
  walk(root,0)
  return {'schema':1,'source_dev':rootst.st_dev,'source_ino':rootst.st_ino,'node_count':nodes,'metadata_groups':[{'kind':k[0],'uid':k[1],'gid':k[2],'mode':k[3],'nlink':k[4],'count':n} for k,n in sorted(counts.items(),key=lambda x:str(x[0]))],'acl_entries':acl,'other_device_entries':other_dev,'live_snapshot':True,'scope':'bounded aggregate metadata only; no paths or contents'}
 finally:os.close(root)
def apply(approved):
 raise RuntimeError('read-only plan only')
