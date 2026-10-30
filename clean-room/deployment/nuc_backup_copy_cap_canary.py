"""Fixed public synthetic backup/restore copy under bridge capabilities.

 Root creates only this disjoint fixture and retains intent and outputs. No
 production journal, service, network, credentials or Docker API is used.
"""
import hashlib,json,os,pathlib,stat
import nuc_grant_sidecar_install as old
ROOT=pathlib.Path('/var/lib/software-factory-goose/backup-copy-cap-canary')
INTENT=old.ETC/'backup-copy-cap-canary-started.json'
DONE=old.ETC/'backup-copy-cap-canary-complete.json'
SOURCE=None
SOURCE_SHA='7748f506082b8ea23dd869923200f6d2868ce81e8ec151f02340017fb66d3f4e'
PUBLIC=b'public synthetic journal copy canary\n'
def require(v,m):
 if not v:raise RuntimeError(m)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'
def capabilities():
 fields=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
 effective=int(fields['CapEff'].strip(),16);require(effective&0x40003==0x40003 and effective&8==0,'bridge capability profile unavailable')
 return {'effective':format(effective,'016x'),'chown':True,'dac_override':True,'sys_chroot':True,'fowner':False}
def plan():
 require(os.geteuid()==0 and os.getegid()==0,'root required');caps=capabilities()
 require(isinstance(SOURCE,bytes) and 0<len(SOURCE)<=65536 and hashlib.sha256(SOURCE).hexdigest()==SOURCE_SHA,'copy source mismatch')
 old.directory(ROOT.parent,0,0,0o711);old.directory(old.ETC,0,0,0o711)
 require(not any(os.path.lexists(p) for p in (ROOT,INTENT,DONE)),'fixture occupied')
 return {'schema':1,'scope':'public synthetic source/copy/restore only; retain all files','root':str(ROOT),'source_sha256':SOURCE_SHA,'capabilities':caps,'production_data':False}
def apply(reviewed):
 require(plan()==reviewed,'canary plan changed');old.store(INTENT,canonical(reviewed),0o600)
 namespace={'__name__':'synthetic_backup_copy'};exec(compile(SOURCE,'<pinned-backup-copy>','exec'),namespace);copy=namespace['copy_tree']
 os.mkdir(ROOT,0o700);os.chmod(ROOT,0o700);old.syncdir(ROOT.parent)
 for name in ('source','backup','restore'):
  path=ROOT/name;os.mkdir(path,0o700);os.chmod(path,0o700);os.chown(path,2004,2004);old.directory(path,2004,2004,0o700)
 source=ROOT/'source';nested=source/'nested';os.mkdir(nested,0o700);os.chmod(nested,0o700)
 fd=os.open(nested/'public.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  os.fchmod(fd,0o600);require(os.write(fd,PUBLIC)==len(PUBLIC),'short fixture write');os.fsync(fd);os.fchown(fd,2004,2004);os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(nested);os.chown(nested,2004,2004);old.syncdir(source);old.syncdir(ROOT)
 def run(src,dst):
  a=os.open(src,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);b=os.open(dst,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:return copy(a,b,2004,2004)
  finally:os.close(a);os.close(b)
 first=run(source,ROOT/'backup');second=run(ROOT/'backup',ROOT/'restore');require(first==second,'restore manifest mismatch')
 path=ROOT/'restore'/'nested'/'public.bin';fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(2004,2004,1,0o600) and os.read(fd,len(PUBLIC)+1)==PUBLIC,'restore bytes or metadata mismatch')
 finally:os.close(fd)
 result={'schema':1,'source_sha256':SOURCE_SHA,'public_copy_equal':True,'restore_equal':True,'uid2004_metadata_equal':True,'no_fowner':True,'production_data':False};old.store(DONE,canonical(result),0o600);return result
