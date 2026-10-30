"""Create-only package install; never reload, enable, start or authorize.

All inputs are public reviewed build artifacts; incomplete operations retain intent.
"""
import hashlib,json,os,pathlib,stat
import nuc_evidence_reader_canary as guard
import nuc_root_authorization_canary as auth

GEN='01M65RMR3F04YB1B016EBBSXGG'
STAGE=pathlib.Path('/tmp/sfactory-finalizer-stage-11v81tfp')
BIN=pathlib.Path('/usr/local/libexec/software-factory-goose')
UNIT=pathlib.Path('/etc/systemd/system')
ETC=pathlib.Path('/etc/software-factory-goose')
RUN=pathlib.Path('/run/software-factory-goose')
AUTH=ETC/'finalization-authorization'
SOCKET_DIR=RUN/'root-finalization'
INTENT=ETC/'root-finalization-package.install-intent'
DONE=ETC/'root-finalization-package.install-complete'
RUNTIME_SHA='28e2c9ab06d8f5286cd2529562fccd15e8a41eb22214ed5a63f6c3b2beeb32f3'
PUBLISHER_SHA='fedc6d1140a22bf4ac9f872f913810f1c2dd30e218d2fc89f8f1c163eb14f66d'
SERVICE_SHA='a069f3fbc07e5240cf73cdb275f34848bc3daee09eded912ef4a10bed9ff36d5'
SOCKET_SHA='6418eb231f7950cb8f29ce6c321553d48c1e96f959f5667e337b1224c67a8dd9'
ITEMS=(('root_finalization_runtime',BIN/'root_finalization_runtime',0o755,RUNTIME_SHA),('root_finalization_publisher',BIN/'root_finalization_publisher',0o755,PUBLISHER_SHA),('software-factory-goose-root-finalization@.service',UNIT/'software-factory-goose-root-finalization@.service',0o644,SERVICE_SHA),('software-factory-goose-root-finalization@.socket',UNIT/'software-factory-goose-root-finalization@.socket',0o644,SOCKET_SHA))

def source(name,digest):
    st=STAGE.lstat();guard.require(stat.S_ISDIR(st.st_mode) and st.st_uid==1000 and st.st_gid==1000 and stat.S_IMODE(st.st_mode)==0o700,'stage directory mismatch');guard.no_acl(STAGE)
    fd=os.open(STAGE/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno());guard.require(stat.S_ISREG(a.st_mode) and a.st_uid==1000 and a.st_gid==1000 and a.st_nlink==1 and stat.S_IMODE(a.st_mode) in (0o644,0o755) and 0<a.st_size<=64*1024*1024,'source metadata mismatch')
        raw=f.read(64*1024*1024+1);b=os.fstat(f.fileno())
        guard.require((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and len(raw)==a.st_size and hashlib.sha256(raw).hexdigest()==digest,'source changed')
        return raw

def plan():
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required')
    guard.require(all(len(x)==64 and all(c in '0123456789abcdef' for c in x) for x in (RUNTIME_SHA,PUBLISHER_SHA)),'production binaries not pinned')
    for directory,mode in ((BIN,0o755),(UNIT,0o755),(RUN,0o755),(AUTH,0o755)):
        guard.ancestors(directory/'placeholder');st=directory.lstat();guard.require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==mode,'protected directory mismatch');guard.no_acl(directory)
    for p in (INTENT,DONE,SOCKET_DIR,AUTH/(GEN+'.lock'),*(item[1] for item in ITEMS)):
        guard.require(not os.path.lexists(p),'create-only target occupied')
    items=[]
    for name,target,mode,digest in ITEMS:
        raw=source(name,digest);items.append({'source':str(STAGE/name),'target':str(target),'mode':oct(mode),'size':len(raw),'sha256':digest})
    return {'schema':1,'purpose':'finalization-package-install-only','generation':GEN,'items':items,'authorization_lock':'root:2000 0440','socket_directory':'root:1000 0710','activation':False,'authorization':False}

def apply(reviewed):
    guard.require(plan()==reviewed,'reviewed package plan changed')
    auth.create(INTENT,(json.dumps(reviewed,sort_keys=True)+'\n').encode(),0o600)
    for name,target,mode,digest in ITEMS:
        raw=source(name,digest)
        auth.create(target,raw,mode)
        del raw
        h=hashlib.sha256()
        with target.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
        guard.require(h.hexdigest()==digest,'installed digest mismatch')
    auth.create(AUTH/(GEN+'.lock'),b'',0o440,2000)
    os.mkdir(SOCKET_DIR,0o710);os.chown(SOCKET_DIR,0,1000,follow_symlinks=False);os.chmod(SOCKET_DIR,0o710,follow_symlinks=False);auth.syncdir(RUN)
    st=SOCKET_DIR.lstat();guard.require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and st.st_gid==1000 and stat.S_IMODE(st.st_mode)==0o710,'socket directory mismatch');guard.no_acl(SOCKET_DIR)
    result={'schema':1,'status':'installed-not-activated','authorized':False}
    auth.create(DONE,(json.dumps(result,sort_keys=True)+'\n').encode(),0o600)
    return result
