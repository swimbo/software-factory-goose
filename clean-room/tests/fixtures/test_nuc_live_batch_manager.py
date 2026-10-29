#!/usr/bin/env python3
import os, pathlib, tempfile, unittest
from unittest.mock import patch
import nuc_live_batch_recovery as recovery

class Tests(unittest.TestCase):
 def test_recovery_refuses_missing_manifest_without_success_marker(self):
  with tempfile.TemporaryDirectory(dir='/tmp') as name:
   root=pathlib.Path(name).resolve(); os.chmod(root,0o700)
   with patch('sys.argv',['recovery',str(root)]), patch.object(recovery,'Batch') as batch:
    with self.assertRaises(RuntimeError): recovery.main()
    batch.assert_not_called(); self.assertFalse((root/'recovery-verified').exists())
 def test_recovery_marks_only_confirmed_stop(self):
  with tempfile.TemporaryDirectory(dir='/tmp') as name:
   root=pathlib.Path(name).resolve(); os.chmod(root,0o700); (root/'manifest').mkdir(mode=0o700)
   with patch('sys.argv',['recovery',str(root)]), patch.object(recovery,'Batch') as batch:
    batch.return_value.stop.return_value=False
    with self.assertRaises(RuntimeError): recovery.main()
    self.assertFalse((root/'recovery-verified').exists())
    batch.return_value.stop.return_value=True; recovery.main()
    self.assertEqual((root/'recovery-verified').read_text(),'verified empty worker slice\n')
if __name__=='__main__': unittest.main()
