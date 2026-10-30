import unittest
from unittest.mock import patch
import nuc_real_grant_rust_probe as p
class ProbeTests(unittest.TestCase):
 def test_changed_plan_fails_before_memfd_or_receipt(self):
  with patch.object(p,'build_plan',return_value=({'version':2},b'binary')),patch.object(p.os,'memfd_create',create=True) as memfd,patch.object(p.os,'open') as opened:
   with self.assertRaises(RuntimeError):p.apply(p.Host('source'),{'version':1})
   memfd.assert_not_called();opened.assert_not_called()
if __name__=='__main__':unittest.main()
