#!/usr/bin/env python3
"""ExecStopPost recovery for the fixed, task-owned live fixture; retain all records."""
import os, pathlib, sys
from docker_batch_guardian import Batch, APPROVED_SLICE, CGROUP_PATH

def main():
 if len(sys.argv)!=2: raise RuntimeError('expected batch root')
 root=pathlib.Path(sys.argv[1])
 if root.resolve(strict=True)!=root or root.is_symlink() or root.stat().st_uid!=os.getuid() or root.stat().st_mode & 0o777 != 0o700:
  raise RuntimeError('untrusted batch root')
 manifest=root/'manifest'
 if not manifest.is_dir() or manifest.is_symlink():
  raise RuntimeError('no durable batch manifest; recovery unresolved')
 if not Batch(manifest,APPROVED_SLICE,CGROUP_PATH).stop():
  raise RuntimeError('batch recovery unresolved')
 fd=os.open(root/'recovery-verified',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as out:
  out.write('verified empty worker slice\n'); out.flush(); os.fsync(out.fileno())
 parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(parent)
 finally: os.close(parent)
if __name__=='__main__': main()
