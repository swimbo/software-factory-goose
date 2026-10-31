import subprocess,unittest
from unittest.mock import patch
import nuc_unix_admin_canary_registration as m
class Registration(unittest.TestCase):
 def test_timeout_preserves_only_start(self):
  seen=[];p={'schema':1,'role':'old'}
  with patch.object(m,'ROLE','old'),patch.object(m,'plan',return_value=p),patch.object(m.old,'store',side_effect=lambda path,*_:seen.append(path.name)),patch.object(m.subprocess,'run',side_effect=subprocess.TimeoutExpired('systemd-run',40)):
   with self.assertRaises(subprocess.TimeoutExpired):m.apply(p)
  self.assertEqual(seen,['unix-admin-canary-register-old-started.json'])
if __name__=='__main__':unittest.main()
