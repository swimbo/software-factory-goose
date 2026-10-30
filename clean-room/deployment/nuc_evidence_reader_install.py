#!/usr/bin/env python3
"""Create-only installation of one prebuilt public synthetic canary, never activation."""
import hashlib, json, os, pathlib, stat, sys
import nuc_evidence_reader_canary as canary

SOURCE = pathlib.Path('/tmp/sfactory-reader-stage-gxdq4z4c/root_evidence_reader_canary')
TARGET = canary.BINARY
INTENT = TARGET.parent / 'root_evidence_reader_canary.install-intent'
EXPECTED = canary.BINARY_SHA256

def source_bytes():
    fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as src:
        st = os.fstat(src.fileno())
        canary.require(stat.S_ISREG(st.st_mode) and st.st_uid == 1000 and st.st_gid == 1000 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o755 and 0 < st.st_size <= 64*1024*1024, 'source metadata mismatch')
        data = src.read(64*1024*1024+1)
        after = os.fstat(src.fileno())
        canary.require((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'source changed')
    canary.require(hashlib.sha256(data).hexdigest() == EXPECTED, 'source digest mismatch')
    return data

def plan():
    canary.require(os.geteuid() == 0 and os.getegid() == 0, 'root required')
    canary.ancestors(TARGET)
    canary.require(not os.path.lexists(TARGET), 'target already exists')
    canary.require(not os.path.lexists(INTENT), 'install intent already exists')
    data = source_bytes()
    return {'schema':1, 'action':'create-only-public-synthetic-canary', 'source':str(SOURCE), 'target':str(TARGET), 'sha256':EXPECTED, 'size':len(data), 'mode':'0755', 'starts_service':False}

def apply(reviewed):
    canary.require(plan() == reviewed, 'reviewed installation changed')
    data = source_bytes()
    intent_fd = os.open(INTENT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(intent_fd, 'wb') as intent:
        intent.write((json.dumps(reviewed, sort_keys=True, separators=(',', ':'))+'\n').encode()); intent.flush(); os.fsync(intent.fileno())
    parent_fd = os.open(TARGET.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o755)
    with os.fdopen(fd, 'wb') as dest:
        os.fchmod(dest.fileno(), 0o755)
        dest.write(data); dest.flush(); os.fsync(dest.fileno())
        st = os.fstat(dest.fileno())
        canary.require(st.st_uid == 0 and st.st_gid == 0 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o755, 'installed metadata mismatch')
    fd = os.open(TARGET.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    canary.require(canary.binary_digest() == EXPECTED, 'installed digest mismatch')
    return {'status':'installed-not-activated', 'sha256':EXPECTED}

def digest(plan_value):
    return hashlib.sha256(json.dumps(plan_value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

if __name__ == '__main__':
    if sys.argv == [sys.argv[0], 'plan']:
        p=plan();print(json.dumps({'plan':p,'sha256':digest(p)},sort_keys=True))
    elif len(sys.argv) == 3 and sys.argv[1] == 'apply':
        p=plan();canary.require(sys.argv[2] == digest(p), 'reviewed plan digest mismatch');print(json.dumps(apply(p),sort_keys=True))
    else: raise RuntimeError('expected plan or apply with plan digest')
