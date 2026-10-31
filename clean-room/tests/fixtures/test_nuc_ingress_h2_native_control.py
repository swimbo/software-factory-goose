import io,unittest
from unittest.mock import patch
import nuc_ingress_h2_native_control as c
class ControlTest(unittest.TestCase):
 def test_line_requires_exact_result_and_readiness(self):
  class P: stdout=io.BytesIO(b'reuse-ok\n')
  p=P()
  with patch.object(c.select,'select',return_value=([p.stdout],[],[])):c.line(p,b'reuse-ok')
  p.stdout=io.BytesIO(b'other\n')
  with patch.object(c.select,'select',return_value=([p.stdout],[],[])), self.assertRaises(RuntimeError):c.line(p,b'reuse-ok')
  with patch.object(c.select,'select',return_value=([],[],[])), self.assertRaises(RuntimeError):c.line(p,b'reuse-ok')
