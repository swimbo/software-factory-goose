"""Create-only install of the fixed read-only native readiness binary."""
import hashlib,os,pathlib,stat
import nuc_evidence_reader_canary as guard
import nuc_root_authorization_canary as auth

STAGE=pathlib.Path('/tmp/sfactory-finalization-readiness-stage-cc3z58v4')
TARGET=pathlib.Path('/usr/local/libexec/software-factory-goose/root_finalization_readiness')
INTENT=TARGET.parent/'root-finalization-readiness.install-intent'
SHA='88aba613a5b7816590782d12c2d0d04aaae56abcc9d9cdba093529d3b3f7e316'

def source():
    st=STAGE.lstat();guard.require(stat.S_ISDIR(st.st_mode) and st.st_uid==1000 and st.st_gid==1000 and stat.S_IMODE(st.st_mode)==0o700,'source root mismatch');guard.no_acl(STAGE)
    fd=os.open(STAGE/'root_finalization_readiness',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());guard.require(stat.S_ISREG(a.st_mode) and a.st_uid==1000 and a.st_gid==1000 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o755 and 0<a.st_size<=64*1024*1024,'source mismatch')
        raw=f.read(64*1024*1024+1);b=os.fstat(f.fileno());guard.require((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and len(raw)==a.st_size and hashlib.sha256(raw).hexdigest()==SHA,'source changed')
        return raw

def plan():
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required');guard.ancestors(TARGET)
    guard.require(not os.path.lexists(TARGET) and not os.path.lexists(INTENT),'target occupied')
    raw=source();return {'schema':1,'purpose':'fixed-root-readiness-install-only','source':str(STAGE/'root_finalization_readiness'),'target':str(TARGET),'sha256':SHA,'size':len(raw),'activation':False}

def apply(reviewed):
    import json
    guard.require(plan()==reviewed,'plan changed');raw=source()
    auth.create(INTENT,(json.dumps(reviewed,sort_keys=True)+'\n').encode(),0o600)
    auth.create(TARGET,raw,0o755);auth.pin(TARGET,SHA)
    return {'status':'installed-not-run','authorized':False}
