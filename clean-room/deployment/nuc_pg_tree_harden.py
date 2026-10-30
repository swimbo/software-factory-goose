#!/usr/bin/env python3
"""One-shot hardening of exactly the reviewed PostgreSQL tree's 62 directories.

Run only after independent review through the host-root bridge. A started intent,
partial receipt, uncertain operation or occupied output requires reconciliation;
this program never rolls back, recursively chmods or automatically retries.
"""
import errno
import hashlib
import json
import os
import pathlib
import stat
import sys

PG=pathlib.Path('/usr/local/libexec/software-factory-goose/postgresql17')
SOURCE=pathlib.Path('/tmp/sfactory-pg1711-build.vfNv9w4h/staged-tree.json')
SOURCE_HASH='39216b7ac1e082074b9e6098e5a3c94a0d706a1910cc302b9df0eddd4d9d23e5'
ETC=pathlib.Path('/etc/software-factory-goose')
INTENT=ETC/'postgres-harden-started.json'
STEPS=ETC/'postgres-harden-steps.jsonl'
MANIFEST=ETC/'postgres-hardened-manifest.json'
DONE=ETC/'postgres-harden-complete.json'


def require(ok,message):
 if not ok:raise RuntimeError(message)


def xattrs(fd,directory):
 for attr in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(fd,attr)
  except OSError as e:require(e.errno==errno.ENODATA,'ACL unavailable')
  else:raise RuntimeError('ACL forbidden')


def open_path(rootfd, relative, directory):
 parts=relative.split('/')
 require(all(x not in ('','.','..') for x in parts) and not relative.startswith('/'),'invalid manifest path')
 fd=os.dup(rootfd)
 try:
  for index,part in enumerate(parts):
   flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
   if index<len(parts)-1 or directory:flags|=os.O_DIRECTORY
   child=os.open(part,flags,dir_fd=fd);os.close(fd);fd=child
  return fd
 except BaseException:
  os.close(fd);raise


def source_manifest():
 fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=2_000_000,'manifest unavailable')
  data=bytearray()
  while len(data)<=2_000_000:
   chunk=os.read(fd,min(65536,2_000_001-len(data)))
   if not chunk:break
   data.extend(chunk)
  require(len(data)==st.st_size and hashlib.sha256(data).hexdigest()==SOURCE_HASH,'manifest hash mismatch')
 finally:os.close(fd)
 parsed=json.loads(data);require(set(parsed)=={'format','entries'} and parsed['format']==1,'manifest format mismatch')
 return parsed


def inspect_tree(root, manifest, uid=0, gid=0):
 rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  rootst=os.fstat(rootfd);require(rootst.st_uid==uid and rootst.st_gid==gid and stat.S_IMODE(rootst.st_mode)==0o755,'tree root mismatch');xattrs(rootfd,True)
  entries=manifest['entries'];expected=set()
  for e in entries:
   p=e['path'];require(isinstance(p,str) and p not in expected and all(x not in ('','.','..') for x in p.split('/')) and not p.startswith('/'),'invalid path')
   expected.add(p)
  actual=set()
  for rootname,dirs,files,_ in os.fwalk('.',dir_fd=rootfd,follow_symlinks=False):
   prefix='' if rootname=='.' else rootname.removeprefix('./')+'/'
   actual.update(prefix+n for n in dirs+files)
  require(actual==expected,'tree entry set mismatch')
  targets=[]
  for e in entries:
   path=e['path'];kind=e['type'];mode=int(e['mode'],8)
   if kind=='symlink':
    parent,_,name=path.rpartition('/')
    parentfd=open_path(rootfd,parent,True) if parent else os.dup(rootfd)
    try:
     st=os.stat(name,dir_fd=parentfd,follow_symlinks=False)
     require(stat.S_ISLNK(st.st_mode) and st.st_uid==uid and st.st_gid==gid and stat.S_IMODE(st.st_mode)==mode,'symlink identity mismatch')
     require(os.readlink(name,dir_fd=parentfd)==e['target'] and '/' not in e['target'] and e['target'] not in ('.','..'),'symlink target mismatch')
    finally:os.close(parentfd)
    continue
   require(kind in ('directory','file'),'unsupported tree entry')
   fd=open_path(rootfd,path,kind=='directory')
   try:
    st=os.fstat(fd);require(st.st_uid==uid and st.st_gid==gid and stat.S_IMODE(st.st_mode)==mode,'owner or mode mismatch')
    xattrs(fd,kind=='directory')
    if kind=='directory':
     require(stat.S_ISDIR(st.st_mode) and mode in (0o755,0o775),'unsafe directory')
     if mode==0o775:targets.append({'path':path,'dev':st.st_dev,'ino':st.st_ino})
    else:
     require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==e['size'] and not mode&0o022,'unsafe regular file')
     sha=hashlib.sha256();count=0
     while True:
      b=os.read(fd,65536)
      if not b:break
      count+=len(b);require(count<=st.st_size,'file grew');sha.update(b)
     require(count==st.st_size and sha.hexdigest()==e['sha256'],'file digest mismatch')
   finally:os.close(fd)
  return {'tree_dev':rootst.st_dev,'tree_ino':rootst.st_ino,'targets':targets}
 finally:os.close(rootfd)


def store(path, data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  os.fchmod(fd,0o600);view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)


def preflight():
 require(os.geteuid()==0,'root required')
 for path,mode in [(pathlib.Path('/'),0o755),(pathlib.Path('/etc'),0o755),(ETC,0o711),(pathlib.Path('/usr'),0o755),(pathlib.Path('/usr/local'),0o755),(pathlib.Path('/usr/local/libexec'),0o755),(PG.parent,0o755)]:
  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);require(st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==mode,'unsafe root ancestor');xattrs(fd,True)
  finally:os.close(fd)
 require(not any(os.path.lexists(path) for path in (INTENT,STEPS,MANIFEST,DONE)),'prior hardening exists; reconcile')
 manifest=source_manifest(); tree=inspect_tree(PG,manifest)
 require(len(tree['targets'])==62,'unexpected target count')
 return {'format':1,'machine_sha256':hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes().strip()).hexdigest(),
         'source_manifest_sha256':SOURCE_HASH,**tree}


def apply(plan):
 require(preflight()==plan,'reviewed plan changed')
 manifest=source_manifest();store(INTENT,json.dumps(plan,sort_keys=True,separators=(',',':')).encode()+b'\n')
 fdlog=os.open(STEPS,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 rootfd=os.open(PG,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  os.fsync(fdlog);pfd=os.open(ETC,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(pfd);os.close(pfd)
  for target in plan['targets']:
   fd=open_path(rootfd,target['path'],True)
   try:
    st=os.fstat(fd);require((st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(target['dev'],target['ino'],0,0,0o775),'target changed')
    xattrs(fd,True);os.fchmod(fd,0o755);os.fsync(fd)
    st=os.fstat(fd);require((st.st_dev,st.st_ino,stat.S_IMODE(st.st_mode))==(target['dev'],target['ino'],0o755),'hardening verification failed')
    record=json.dumps(target,sort_keys=True,separators=(',',':')).encode()+b'\n'
    view=memoryview(record)
    while view:
     n=os.write(fdlog,view);require(n>0,'short receipt');view=view[n:]
    os.fsync(fdlog)
   finally:os.close(fd)
 finally:os.close(rootfd);os.close(fdlog)
 targets={x['path'] for x in plan['targets']}
 for entry in manifest['entries']:
  if entry['path'] in targets:entry['mode']='0o755'
 verified=inspect_tree(PG,manifest);require(not verified['targets'],'hardened tree remains writable')
 data=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()+b'\n';digest=hashlib.sha256(data).hexdigest()
 store(MANIFEST,data)
 store(DONE,json.dumps({'format':1,'source_manifest_sha256':SOURCE_HASH,'hardened_manifest_sha256':digest,'directory_count':62,'tree_dev':plan['tree_dev'],'tree_ino':plan['tree_ino']},sort_keys=True,separators=(',',':')).encode()+b'\n')
 print(json.dumps({'hardened_manifest_sha256':digest,'directory_count':62},sort_keys=True))


if __name__=='__main__':
 if sys.argv==[sys.argv[0],'--plan']:print(json.dumps(preflight(),sort_keys=True,indent=2))
 elif sys.argv==[sys.argv[0],'--apply']:
  raw=sys.stdin.buffer.read(1_000_001);require(len(raw)<=1_000_000,'plan too large');apply(json.loads(raw))
 else:raise SystemExit('expected --plan or --apply')
