#!/usr/bin/env python3
"""Review-only, create-only install of fixed synthetic fixture binaries."""
import hashlib,json,os,pathlib,stat
import nuc_evidence_reader_canary as guard
import nuc_root_authorization_canary as auth
import nuc_finalization_journal_fixture as fixture

SOURCE=pathlib.Path('/tmp/sfactory-journal-stage-wf50evnd')
TARGET=pathlib.Path('/usr/local/libexec/software-factory-goose')
INTENT=TARGET/'finalization-journal-fixture.install-intent'
BINARIES=(('finalization_runtime_fixture','finalization_journal_fixture',fixture.SDK_SHA),('root_authorization_journal_fixture','root_authorization_journal_fixture',fixture.PUBLISHER_SHA),('finalization_pg_attestor.py','finalization_pg_attestor.py',fixture.ATTESTOR_SHA))

def load(name,digest):
    root=SOURCE
    st=root.lstat();guard.require(stat.S_ISDIR(st.st_mode) and st.st_uid==1000 and st.st_gid==1000 and stat.S_IMODE(st.st_mode)==0o700,'untrusted source root')
    guard.no_acl(root)
    source=root/('nuc_finalization_pg_attestor.py' if name=='finalization_pg_attestor.py' else name)
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno());guard.require(stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_gid==1000 and before.st_nlink==1 and stat.S_IMODE(before.st_mode) in ((0o644,0o755) if name=='finalization_pg_attestor.py' else (0o755,)) and 0<before.st_size<=64*1024*1024,'source metadata mismatch')
        data=f.read(64*1024*1024+1);after=os.fstat(f.fileno())
        guard.require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(data)==before.st_size and hashlib.sha256(data).hexdigest()==digest,'source changed')
    return data

def plan():
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required');guard.ancestors(TARGET/'fixture')
    guard.require(not os.path.lexists(INTENT),'install intent occupied')
    entries=[]
    for source,target,digest in BINARIES:
        guard.require(not os.path.lexists(TARGET/target),'target occupied')
        raw=load(source,digest);entries.append({'source':str((SOURCE/'nuc_finalization_pg_attestor.py') if source=='finalization_pg_attestor.py' else (SOURCE/source)),'target':str(TARGET/target),'sha256':digest,'size':len(raw)})
    return {'schema':1,'purpose':'synthetic-journal-binaries-install-only','binaries':entries,'activation':False}

def apply(reviewed):
    guard.require(plan()==reviewed,'install plan changed')
    data=[(target,load(source,digest),digest) for source,target,digest in BINARIES]
    auth.create(INTENT,(json.dumps(reviewed,sort_keys=True)+'\n').encode(),0o600)
    for target,raw,digest in data:
        auth.create(TARGET/target,raw,0o755);auth.pin(TARGET/target,digest)
    return {'status':'installed-not-started','intent_retained':True}
