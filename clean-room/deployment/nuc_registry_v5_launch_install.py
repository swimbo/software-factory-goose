"""Create-only installation of a distinct pinned SDK5 native helper; never execute."""
import hashlib,json,os,pathlib,stat
import nuc_evidence_reader_canary as guard
import nuc_root_authorization_canary as auth


STAGE=pathlib.Path('/tmp/sfactory-sdk5-launch-stage-gania_9u')
SOURCE=STAGE/'sfactory_root_launch'
TARGET=pathlib.Path('/usr/local/libexec/software-factory-goose/root-launch-v5')
SHA='69eb73550285da18c216ab50944f1aca547841098bb6e5628255c3b2cc0be7c6'
INTENT=TARGET.parent/'root-launch-v5.install-intent'
DONE=TARGET.parent/'root-launch-v5.install-complete'

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
    raw=read_source();return {'schema':1,'purpose':'SDK5-native-launch-install-only','source':str(SOURCE),'target':str(TARGET),'sha256':SHA,'size':len(raw),'execute':False,'activation':False}

def apply(reviewed):
    guard.require(plan()==reviewed,'reviewed plan changed');raw=read_source()
    auth.create(INTENT,(json.dumps(reviewed,sort_keys=True)+'\n').encode(),0o600)
    auth.create(TARGET,raw,0o755);auth.pin(TARGET,SHA)
    result={'schema':1,'installed':True,'executed':False,'activated':False};auth.create(DONE,(json.dumps(result,sort_keys=True)+'\n').encode(),0o600)
    return result
