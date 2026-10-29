#!/usr/bin/env python3
"""Isolated fixed-helper tests; no Docker or host cgroup mutation."""
import json,os,pathlib,shutil,subprocess,sys,tempfile,unittest
SOURCE=pathlib.Path(__file__).with_name('docker_batch_brake_cleanup.py')
class Tests(unittest.TestCase):
 def run_case(self,tampered=False):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); cg=root/'cg'; cg.mkdir(); (root/'manifest').mkdir(); trace=root/'trace'; token='a'*32; sl='fixed.slice'
   binding={'token':('b'*32 if tampered else token),'slice':sl,'inode':cg.stat().st_ino}
   f=root/'brake-binding.json';f.write_text(json.dumps(binding));f.chmod(0o600)
   shutil.copyfile(SOURCE,root/'cleanup.py')
   fake="import pathlib\\nAPPROVED_SLICE="+repr(sl)+"\\nCGROUP_PATH=pathlib.Path("+repr(str(cg))+")\\nclass Batch:\\n def __init__(self,*args): self.n=0\\n def stop(self):\\n  self.n+=1; open("+repr(str(trace))+",'a').write('S')\\n  if self.n==1: raise BlockingIOError()\\n  return True\\n"
   (root/'docker_batch_guardian.py').write_text(fake.replace('\\n','\n'))
   p=subprocess.run([sys.executable,str(root/'cleanup.py'),str(root),token],capture_output=True,text=True,timeout=5)
   if tampered:
    self.assertNotEqual(p.returncode,0);self.assertFalse(trace.exists());self.assertFalse((root/'cleanup-result').exists())
   else:
    self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(trace.read_text(),'SS');self.assertEqual((root/'cleanup-result').read_text(),'OK COMMITTED '+str(cg.stat().st_ino))
 def test_busy_retry_then_verified(self): self.run_case()
 def test_binding_mismatch_fails_before_stop(self): self.run_case(tampered=True)
if __name__=='__main__':unittest.main()
