import contextlib
import hashlib
import io
import json
import pathlib
import tempfile
import unittest
from nuc_int_loop_task import create, check, finalize

class HoldoutControls(unittest.TestCase):
 def test_constant_greeting_is_rejected(self):
  with tempfile.TemporaryDirectory() as parent:
   root=pathlib.Path(parent)/'task'
   with contextlib.redirect_stdout(io.StringIO()):create(root)
   repo=root/'repo'
   (repo/'hello.py').write_text('print("hello world")\n')
   (repo/'test_hello.py').write_text('import unittest\nclass Test(unittest.TestCase):\n def test_constant(self):self.assertEqual(1,1)\n')
   with self.assertRaises(AssertionError):check(repo)
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
