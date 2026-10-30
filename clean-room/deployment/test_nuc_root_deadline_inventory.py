import os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import nuc_root_deadline_inventory as d
class InventoryTests(unittest.TestCase):
 def test_fifo_refused_without_blocking(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'fifo';os.mkfifo(p,0o600)
   with self.assertRaises(RuntimeError):d.read(p)
 def test_systemctl_duplicate_property_rejected(self):
  class R:returncode=0;stdout='LoadState=loaded\nLoadState=not-found\n'
  with patch.object(d.subprocess,'run',return_value=R()):
   with self.assertRaises(RuntimeError):d.unit('fixed.service')
if __name__=='__main__':unittest.main()
