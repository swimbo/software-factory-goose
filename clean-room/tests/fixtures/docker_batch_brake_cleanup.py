#!/usr/bin/env python3
"""Fixture-only fixed batch cleanup entry for the authenticated brake example."""
import json, os, pathlib, stat, sys, time
from docker_batch_guardian import Batch, APPROVED_SLICE, CGROUP_PATH


def main():
    if len(sys.argv) != 3: raise RuntimeError('fixture root and token required')
    root=pathlib.Path(sys.argv[1]); token=sys.argv[2]
    if len(token)!=32 or any(c not in '0123456789abcdef' for c in token): raise RuntimeError('invalid binding token')
    fd=os.open(root/'brake-binding.json',os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        st=os.fstat(f.fileno())
        if st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or not stat.S_ISREG(st.st_mode): raise RuntimeError('unsafe brake binding')
        binding=json.load(f)
    if binding != {'token':token,'slice':APPROVED_SLICE,'inode':CGROUP_PATH.stat().st_ino}:
        raise RuntimeError('brake binding mismatch')
    b=Batch(root/'manifest',APPROVED_SLICE,CGROUP_PATH)
    deadline=time.monotonic()+25
    while True:
        try:
            b.stop(); break
        except BlockingIOError:
            if time.monotonic()>=deadline: raise RuntimeError('batch busy; cleanup unresolved')
            time.sleep(.05)
    fd=os.open(root/'cleanup-result',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:
        f.write('OK COMMITTED '+str(binding['inode'])); f.flush(); os.fsync(f.fileno())
    dirfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(dirfd)
    finally: os.close(dirfd)

if __name__=='__main__': main()
