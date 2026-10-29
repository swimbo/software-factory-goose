#!/usr/bin/env python3
"""Launch the single fixed writer live fixture under an owned user manager unit.

The caller must create SFACTORY_BATCH_ROOT as a private empty directory and
retain it, the separate run fence and candidate after any outcome.
"""
import os, pathlib, re, stat, subprocess, sys, uuid
ROOT=pathlib.Path('/tmp/sfactory-tool-relay-code.f6O9xEoS')
DRIVER=ROOT/'nuc_goose_live_writer7_batch.py'
RECOVERY=ROOT/'nuc_live_batch_recovery.py'

def main():
 if sys.argv!=[sys.argv[0],'--start-attempt7'] or os.getuid()!=1000: raise RuntimeError('explicit task scope required')
 root=pathlib.Path(os.environ['SFACTORY_BATCH_ROOT'])
 if not re.fullmatch(r'/tmp/[A-Za-z0-9_.-]+',str(root)) or root.resolve(strict=True)!=root or root.is_symlink() or root.stat().st_uid!=1000 or stat.S_IMODE(root.stat().st_mode)!=0o700 or any(root.iterdir()):
  raise RuntimeError('batch root must be empty, canonical and private')
 for path in (DRIVER,RECOVERY):
  st=path.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=1000 or st.st_nlink!=1 or st.st_mode & 0o022:
   raise RuntimeError('fixed fixture program unavailable')
 unit='sfactory-writer-live-'+uuid.uuid4().hex+'.service'
 probe=subprocess.run(['systemctl','--user','show',unit,'-p','LoadState','--value'],capture_output=True,text=True,check=False,timeout=10)
 if probe.stdout.strip() not in ('','not-found'): raise RuntimeError('unit collision')
 fd=os.open(root/'unit',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as out:
  out.write(unit+'\n'); out.flush(); os.fsync(out.fileno())
 parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(parent)
 finally: os.close(parent)
 command=['systemd-run','--user','--unit='+unit,'--collect','--property=Description='+unit,
  '--property=RuntimeMaxSec=240s','--property=TimeoutStopSec=60s','--property=KillMode=control-group',
  '--property=StandardOutput=append:'+str(root/'output.log'),'--property=StandardError=append:'+str(root/'output.log'),
  '--property=ExecStopPost=/usr/bin/python3 '+str(RECOVERY)+' '+str(root),
  '--setenv=SFACTORY_BATCH_ROOT='+str(root),'--setenv=SFACTORY_LIVE_ATTEMPT=7','/usr/bin/python3',str(DRIVER),'--live']
 subprocess.run(command,capture_output=True,text=True,check=True,timeout=10)
 print(unit,flush=True)
if __name__=='__main__': main()
