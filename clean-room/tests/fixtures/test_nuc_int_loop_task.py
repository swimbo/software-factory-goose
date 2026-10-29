import contextlib
import hashlib
import io
import json
import pathlib
import tempfile
import subprocess
import sys
import unittest
from unittest import mock
import nuc_int_loop_task
from nuc_int_loop_task import create, check_behavior, finalize

class HoldoutControls(unittest.TestCase):
 def test_each_scenario_runs_three_times_and_requires_two_votes(self):
  seen={}
  def candidate(*args):
   seen[args]=seen.get(args,0)+1
   if seen[args]==1 and args in ((),('Ada',)):return subprocess.CompletedProcess(args,1,b'',b'transient')
   if args in (('a','b'),('--bogus',)):return subprocess.CompletedProcess(args,2,b'',b'usage')
   name=next((a for a in args if a!='--uppercase'),'world')
   text='hello '+name
   if '--uppercase' in args:text=text.upper()
   return subprocess.CompletedProcess(args,0,(text+'\n').encode(),b'')
  tests=lambda:subprocess.CompletedProcess([],0,b'',b'Ran 1 test\nOK')
  result=check_behavior(candidate,tests,{})
  self.assertEqual(list(seen.values()),[3]*7)
  self.assertEqual(result['scenario_votes'],[2,2,3,3,3,3,3])
 def test_two_of_three_everywhere_still_fails_aggregate(self):
  seen={}
  def candidate(*args):
   seen[args]=seen.get(args,0)+1
   if seen[args]==1:return subprocess.CompletedProcess(args,1,b'',b'transient')
   if args in (('a','b'),('--bogus',)):return subprocess.CompletedProcess(args,2,b'',b'usage')
   text='hello '+next((a for a in args if a!='--uppercase'),'world')
   if '--uppercase' in args:text=text.upper()
   return subprocess.CompletedProcess(args,0,(text+'\n').encode(),b'')
  with self.assertRaisesRegex(RuntimeError,'aggregate below 90'):check_behavior(candidate,lambda:None,{})
 def test_one_good_vote_does_not_pass(self):
  seen={}
  def candidate(*args):
   seen[args]=seen.get(args,0)+1
   return subprocess.CompletedProcess(args,0,b'hello world\n' if seen[args]==1 else b'wrong\n',b'')
  with self.assertRaisesRegex(RuntimeError,'greeting behavior'):check_behavior(candidate,lambda:None,{})
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
   (root/'holdout-result.json').write_text(json.dumps({'groups':['pass']*3,'repetitions':3,'scenario_votes':[3]*7,'candidate_tests':'pass','files':digests}))
   (repo/'hello.py').write_text('# changed after evaluation\n')
   with self.assertRaisesRegex(RuntimeError,'evaluated content changed'):finalize(root)
 def test_old_single_run_report_cannot_finalize(self):
  with tempfile.TemporaryDirectory() as parent:
   root=pathlib.Path(parent)/'task'
   with contextlib.redirect_stdout(io.StringIO()):create(root)
   for name in ('hello.py','test_hello.py'):(root/'repo'/name).write_text('# evaluated\n')
   files={name:hashlib.sha256((root/'repo'/name).read_bytes()).hexdigest() for name in ('hello.py','test_hello.py')}
   (root/'holdout-result.json').write_text(json.dumps({'groups':['pass']*3,'candidate_tests':'pass','files':files}))
   with self.assertRaisesRegex(RuntimeError,'repetition evidence missing'):finalize(root)
   self.assertEqual(nuc_int_loop_task.git(root/'repo','rev-parse','HEAD'),json.loads((root/'task.json').read_text())['baseline'])
 def test_finalizer_also_enforces_aggregate(self):
  with tempfile.TemporaryDirectory() as parent:
   root=pathlib.Path(parent)/'task'
   with contextlib.redirect_stdout(io.StringIO()):create(root)
   for name in ('hello.py','test_hello.py'):(root/'repo'/name).write_text('# evaluated\n')
   files={name:hashlib.sha256((root/'repo'/name).read_bytes()).hexdigest() for name in ('hello.py','test_hello.py')}
   (root/'holdout-result.json').write_text(json.dumps({'groups':['pass']*3,'candidate_tests':'pass','files':files,'repetitions':3,'scenario_votes':[2]*7}))
   with self.assertRaisesRegex(RuntimeError,'aggregate below 90'):finalize(root)
   self.assertFalse((root/'evaluation.json').exists())
 def test_write_between_digest_and_staging_withholds_commit_acceptance(self):
  with tempfile.TemporaryDirectory() as parent:
   root=pathlib.Path(parent)/'task'
   with contextlib.redirect_stdout(io.StringIO()):create(root)
   repo=root/'repo'
   for name in ('hello.py','test_hello.py'):(repo/name).write_text('# evaluated\n')
   files={name:hashlib.sha256((repo/name).read_bytes()).hexdigest() for name in ('hello.py','test_hello.py')}
   (root/'holdout-result.json').write_text(json.dumps({'groups':['pass']*3,'repetitions':3,'scenario_votes':[3]*7,'candidate_tests':'pass','files':files}))
   original=nuc_int_loop_task.git
   def raced_git(directory,*args):
    if args[0]=='add':(repo/'hello.py').write_text('# late change\n')
    return original(directory,*args)
   with mock.patch.object(nuc_int_loop_task,'git',side_effect=raced_git):
    with self.assertRaisesRegex(RuntimeError,'committed content differs'):finalize(root)
   self.assertFalse((root/'evaluation.json').exists())

if __name__=='__main__':unittest.main()
