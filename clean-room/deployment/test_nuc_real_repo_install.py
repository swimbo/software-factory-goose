import hashlib,unittest
from unittest import mock
import nuc_real_repo_install as m
class RealRepoTests(unittest.TestCase):
 def test_codified_task_is_exact_preserved_contract(self):
  self.assertEqual(hashlib.sha256(m.REQUIREMENTS.encode()).hexdigest(),'43f9de594f3d51d570a0756239b99f206bc4ab89a5e314789bba87a894565820')
  self.assertEqual(set(m.FILES),{'README.md','AGENTS.md','requirements.md'})
  self.assertIn('only hello.py and test_hello.py',m.AGENTS)
 def test_occupied_parent_refuses_before_systemd(self):
  with mock.patch.object(m.os,'geteuid',return_value=0),mock.patch.object(m.pwd,'getpwnam') as user,mock.patch.object(m,'safe_dir'),mock.patch.object(m.os.path,'lexists',return_value=True),mock.patch.object(m.subprocess,'run') as run:
   user.return_value.pw_uid=2000
   with self.assertRaises(RuntimeError):m.plan()
   run.assert_not_called()
if __name__=='__main__':unittest.main()
