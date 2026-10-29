import contextlib
import hashlib
import io
import json
import pathlib
import tempfile
import subprocess
import sys
import unittest
from nuc_int_loop_task import create, check_behavior, finalize

class HoldoutControls(unittest.TestCase):
 def test_constant_greeting_is_rejected(self):
  def bad_candidate(*args):
   return subprocess.CompletedProcess(args,0,b'hello world\n',b'')
  def forbidden_tests():raise RuntimeError('must reject before tests')
  with self.assertRaisesRegex(RuntimeError,"greeting behavior"):check_behavior(bad_candidate,forbidden_tests,{})
 def test_optimized_interpreter_still_rejects_bad_candidate(self):
  code="from nuc_int_loop_task import check_behavior; from subprocess import CompletedProcess; check_behavior(lambda *a: CompletedProcess(a,0,b'hello world\\n',b''),lambda:None,{})"
  result=subprocess.run([sys.executable,'-O','-c',code],cwd=pathlib.Path(__file__).parent,capture_output=True)
  self.assertNotEqual(result.returncode,0)
  self.assertIn(b'greeting behavior',result.stderr)
 def test_changed_evaluated_content_cannot_be_committed(self):
  with tempfile.TemporaryDirectory() as parent:
   root=pathlib.Path(parent)/'task'
   with contextlib.redirect_stdout(io.StringIO()):create(root)
   repo=root/'repo'
   for name in ('hello.py','test_hello.py'):(repo/name).write_text('# original\n')
   digests={name:hashlib.sha256((repo/name).read_bytes()).hexdigest() for name in ('hello.py','test_hello.py')}
   (root/'holdout-result.json').write_text(json.dumps({'groups':['pass']*3,'candidate_tests':'pass','files':digests}))
   (repo/'hello.py').write_text('# changed after evaluation\n')
   with self.assertRaisesRegex(RuntimeError,'evaluated content changed'):finalize(root)

if __name__=='__main__':unittest.main()
