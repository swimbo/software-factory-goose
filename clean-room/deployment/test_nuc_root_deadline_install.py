import unittest
from unittest.mock import patch
import nuc_root_deadline_install as d
class InstallTests(unittest.TestCase):
 def test_mismatched_review_denies_before_write(self):
  with patch.object(d.os,'geteuid',return_value=0),patch.object(d,'plan',return_value=({'boot_id':'current'},b'binary')),patch.object(d,'write_new') as write:
   with self.assertRaises(RuntimeError):d.apply({'boot_id':'old'})
   write.assert_not_called()
 def test_collision_denies_before_candidate_read(self):
  with patch.object(d,'directory'),patch.object(d.os.path,'lexists',return_value=True),patch.object(d,'source') as source:
   with self.assertRaises(RuntimeError):d.plan()
   source.assert_not_called()
if __name__=='__main__':unittest.main()
