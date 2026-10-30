"""Create-only installation of a distinct pinned SDK5 native helper; never execute."""
import hashlib,json,os,pathlib,stat
import nuc_evidence_reader_canary as guard
import nuc_root_authorization_canary as auth


STAGE=pathlib.Path('/tmp/sfactory-sdk5-launch-stage-gania_9u')
SOURCE=STAGE/'sfactory_root_grant_prepare'
TARGET=pathlib.Path('/usr/local/libexec/software-factory-goose/registry-v5-grant-prepare')
SHA='a0d032e72e958e1d18ff0b7f945faa2748f46db26dc2ca371a98b84fceddb420'
INTENT=TARGET.parent/'registry-v5-grant-prepare.install-intent'
DONE=TARGET.parent/'registry-v5-grant-prepare.install-complete'

def read_source():
    st=STAGE.lstat();guard.require(stat.S_ISDIR(st.st_mode) and st.st_uid==1000 and st.st_gid==1000 and stat.S_IMODE(st.st_mode)==0o700,'source root mismatch');guard.no_acl(STAGE)
    fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno());guard.require(stat.S_ISREG(before.st_mode) and (before.st_uid,before.st_gid,before.st_nlink,stat.S_IMODE(before.st_mode))==(1000,1000,1,0o755) and 0<before.st_size<=64*1024*1024,'source metadata mismatch')
        raw=f.read(64*1024*1024+1);after=os.fstat(f.fileno());guard.require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==SHA,'source changed')
        return raw

def plan():
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required');guard.ancestors(TARGET)
    guard.require(not any(os.path.lexists(p) for p in (TARGET,INTENT,DONE)),'destination occupied')
    raw=read_source();return {'schema':1,'purpose':'SDK5-native-grant-install-only','source':str(SOURCE),'target':str(TARGET),'sha256':SHA,'size':len(raw),'execute':False,'activation':False}

def apply(reviewed):
    guard.require(plan()==reviewed,'reviewed plan changed');raw=read_source()
    auth.create(INTENT,(json.dumps(reviewed,sort_keys=True)+'\n').encode(),0o600)
    auth.create(TARGET,raw,0o755);auth.pin(TARGET,SHA)
    result={'schema':1,'installed':True,'executed':False,'activated':False};auth.create(DONE,(json.dumps(result,sort_keys=True)+'\n').encode(),0o600)
    return result
