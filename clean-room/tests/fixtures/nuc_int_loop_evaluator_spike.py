#!/usr/bin/env python3
"""NUC negative and owner-loss controls; no inference and no generated host code."""
import hashlib,json,os,pathlib,subprocess,sys,tempfile,time
from nuc_int_loop_evaluator import CGROUP_PATH,launch_manager,store,system

def control(mode):
 root=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-eval-'+mode+'-'));root.chmod(0o700)
 evaluation=root/'evaluation';evaluation.mkdir(mode=0o700);snapshot=evaluation/'snapshot';snapshot.mkdir(mode=0o755)
 code='print("hello world")\n' if mode=='negative' else 'import time;time.sleep(30)\n'
 (snapshot/'hello.py').write_text(code);(snapshot/'test_hello.py').write_text('import unittest\nclass Test(unittest.TestCase):\n def test_fixture(self):self.assertEqual(1,1)\n')
 for path in snapshot.iterdir():path.chmod(0o444)
 snapshot.chmod(0o555);store(evaluation/'snapshot.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in snapshot.iterdir()})
 process=subprocess.Popen([sys.executable,str(pathlib.Path(__file__).resolve()),'launch',str(root),str(evaluation)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 try:
  if mode=='ownerloss':
   deadline=time.monotonic()+30
   while time.monotonic()<deadline:
    if (evaluation/'challenge-0'/'executor.exec').exists() and 'populated 1' in (CGROUP_PATH/'cgroup.events').read_text():break
    if process.poll() is not None:raise RuntimeError('ownerloss control exited before ready')
    time.sleep(.05)
   else:raise RuntimeError('ownerloss control readiness failed')
   record=json.loads((evaluation/'unit.json').read_text());unit=record['unit']
   if system('show',unit,'-p','Description','--value').stdout.strip()!=unit or record['script'] not in system('show',unit,'-p','ExecStart','--value').stdout:raise RuntimeError('unit identity mismatch')
   system('kill','--kill-whom=main','--signal=SIGKILL',unit)
  status=process.wait(timeout=75)
  if status==0 or (evaluation/'result.json').exists() or json.loads((evaluation/'recovered.json').read_text())!={'empty':True} or 'populated 0' not in (CGROUP_PATH/'cgroup.events').read_text():raise RuntimeError('evaluation control failed; retain '+str(root))
  print('PASS: '+mode+' withheld evaluation; exact roots removed; slice populated 0; evidence '+str(root),flush=True)
 finally:
  if process.poll() is None:
   # Retain exact unit record for reconciliation; a local launcher kill alone
   # never counts as sandbox recovery.
   process.kill();process.wait(timeout=5)

if __name__=='__main__':
 if len(sys.argv)>1 and sys.argv[1]=='launch':launch_manager(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]))
 else:
  if os.getuid()!=1000 or 'populated 0' not in (CGROUP_PATH/'cgroup.events').read_text():raise RuntimeError('NUC fixture not ready')
  control('negative');control('ownerloss')
