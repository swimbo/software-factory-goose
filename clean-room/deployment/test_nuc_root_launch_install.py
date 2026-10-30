import unittest
from unittest.mock import patch
import nuc_root_launch_install as d
class InstallTests(unittest.TestCase):
 def test_changed_plan_denies_before_any_write(self):
  with patch.object(d,'build_plan',return_value=({'version':2},(b'a',b'b',b'c'))),patch.object(d,'create') as create:
   with self.assertRaises(RuntimeError):d.apply(d.Host('x'),{'version':1})
   create.assert_not_called()
 def test_root_role_mismatch_denies_before_source_read(self):
  class User:pw_uid=2001;pw_gid=2001
  class Group:gr_gid=2001
  with patch.object(d.os,'geteuid',return_value=0),patch.object(d,'directory'),patch.object(d.pwd,'getpwnam',return_value=User()),patch.object(d.grp,'getgrnam',return_value=Group()),patch.object(d,'read') as read:
   with self.assertRaises(RuntimeError):d.build_plan(d.Host('x'))
   read.assert_not_called()
if __name__=='__main__':unittest.main()
