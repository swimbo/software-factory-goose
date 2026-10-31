import io, unittest
from unittest.mock import patch
import nuc_ingress_fence_probe_h2 as p
class KeeperProtocol(unittest.TestCase):
 def test_fixed_phase_and_dead_keeper(self):
  class Proc:
   stdin=io.BytesIO()
   stdout=io.BytesIO(b'reuse-ok\n')
   def poll(self):return None
  proc=Proc()
  with patch.object(p.select,'select',return_value=([proc.stdout],[],[])):
   p.keeper_command(proc,'reuse','reuse-ok')
  self.assertEqual(proc.stdin.getvalue(),b'reuse\n')
  proc.stdout=io.BytesIO(b'wrong\n')
  with patch.object(p.select,'select',return_value=([proc.stdout],[],[])), self.assertRaises(RuntimeError):
   p.keeper_command(proc,'retired','retired-denied')
 def test_timeout_fails_closed(self):
  class Proc: stdout=io.BytesIO()
  with patch.object(p.select,'select',return_value=([],[],[])), self.assertRaises(RuntimeError):
   p.keeper_line(Proc(),'initial-ok')
