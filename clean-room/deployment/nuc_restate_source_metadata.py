"""Read-only metadata of the fixed Restate source directory; no contents."""
import os,pathlib,stat
import nuc_grant_sidecar_install as old
SOURCE=pathlib.Path('/var/lib/software-factory-goose/journal/restate')
def plan():
 if os.geteuid()!=0:raise RuntimeError('root required')
 fd=os.open(SOURCE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);old.noacl(fd,True);return {'schema':1,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'dev':s.st_dev,'ino':s.st_ino,'directory':stat.S_ISDIR(s.st_mode),'scope':'fixed source metadata only; no contents'}
 finally:os.close(fd)
def apply(approved):
 if plan()!=approved:raise RuntimeError('source changed')
 return approved
