#!/usr/bin/env python3
"""Create-only install of two fixed public synthetic canaries; no unit activation."""
import hashlib,json,os,pathlib,stat,sys
import nuc_evidence_reader_canary as guard
import nuc_root_authorization_canary as fixture

SOURCE=pathlib.Path('/tmp/sfactory-auth-stage-77f9neoq')
PREFIX=pathlib.Path('/usr/local/libexec/software-factory-goose')
INTENT=PREFIX/'root-authorization-canary.install-intent'
BINARIES=(('root_authorization_reader_canary',fixture.READER_SHA),('root_authorization_publisher_canary',fixture.PUB_SHA))

def read_source(name,digest):
    fd=os.open(SOURCE/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());guard.require(stat.S_ISREG(st.st_mode) and st.st_uid==1000 and st.st_gid==1000 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o755 and 0<st.st_size<=64*1024*1024,'source metadata mismatch')
        raw=f.read(64*1024*1024+1);after=os.fstat(f.fileno())
        guard.require((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and hashlib.sha256(raw).hexdigest()==digest,'source changed or digest mismatch')
    return raw

def plan():
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required');guard.ancestors(PREFIX/'fixed-target')
    guard.require(not os.path.lexists(INTENT),'install intent already exists')
    values=[]
    for name,digest in BINARIES:
        guard.require(not os.path.lexists(PREFIX/name),'target already exists')
        data=read_source(name,digest);values.append({'source':str(SOURCE/name),'target':str(PREFIX/name),'sha256':digest,'size':len(data),'mode':'0755'})
    return {'schema':1,'purpose':'synthetic-authorization-canaries-install-only','binaries':values,'starts_service':False}

def apply(reviewed):
    guard.require(plan()==reviewed,'reviewed install scope changed')
    data=[(name,read_source(name,digest)) for name,digest in BINARIES]
    fd=os.open(INTENT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:f.write((json.dumps(reviewed,sort_keys=True,separators=(',',':'))+'\n').encode());f.flush();os.fsync(f.fileno())
    fixture.syncdir(PREFIX)
    for name,raw in data:
        target=PREFIX/name;fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o755)
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),0o755);f.write(raw);f.flush();os.fsync(f.fileno())
            st=os.fstat(f.fileno());guard.require(st.st_uid==0 and st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o755,'installed metadata mismatch')
        fixture.syncdir(PREFIX)
    for name,digest in BINARIES:fixture.pin(PREFIX/name,digest)
    return {'status':'installed-not-activated','binaries':len(data)}

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
if __name__=='__main__':
    if sys.argv==[sys.argv[0],'plan']:
        value=plan();print(json.dumps({'plan':value,'sha256':digest(value)},sort_keys=True))
    elif len(sys.argv)==3 and sys.argv[1]=='apply':
        value=plan();guard.require(sys.argv[2]==digest(value),'reviewed plan digest mismatch');print(json.dumps(apply(value),sort_keys=True))
    else:raise RuntimeError('expected plan or apply with exact plan digest')
