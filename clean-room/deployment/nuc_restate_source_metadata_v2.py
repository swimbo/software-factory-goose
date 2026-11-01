"""Read-only fixed journal/base/node directory metadata; no contents."""
import os,pathlib,stat
import nuc_grant_sidecar_install as old
ROOT=pathlib.Path('/var/lib/software-factory-goose/journal');PATHS=(ROOT,ROOT/'restate',ROOT/'restate'/'sfgoose-private')
def plan():
 if os.geteuid()!=0:raise RuntimeError('root required')
 result={}
 for path in PATHS:
  try:fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  except FileNotFoundError:result[path.name]={'present':False};continue
  try:
   s=os.fstat(fd);old.noacl(fd,True);result[path.name]={'present':True,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'dev':s.st_dev,'ino':s.st_ino,'directory':stat.S_ISDIR(s.st_mode)}
  finally:os.close(fd)
 return {'schema':1,'paths':result,'scope':'fixed directory metadata only; no contents'}
def apply(approved):
 if plan()!=approved:raise RuntimeError('metadata changed')
 return approved
