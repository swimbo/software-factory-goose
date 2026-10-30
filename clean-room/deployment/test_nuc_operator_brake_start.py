import pathlib,tempfile,unittest
from unittest.mock import patch
import nuc_operator_brake_start as m
class BrakeStart(unittest.TestCase):
 def test_partial_install_keeps_intent_and_no_success(self):
  with tempfile.TemporaryDirectory() as td:
   root=pathlib.Path(td);intent=root/'intent';done=root/'done';system=root/'system';system.mkdir()
   spec={'dropin_sha256':{},'boot_id':'test'}
   def store(path,data,mode):
    if path==intent:path.write_bytes(data)
    else:raise OSError('injected drop-in failure')
   with patch.multiple(m,INTENT=intent,DONE=done,SYSTEM=system,DROPS={'fixture.service.d':'[Service]\nMemoryMax=128M\n'}),patch.object(m,'plan',return_value=spec),patch.object(m.old,'store',side_effect=store),patch.object(m.old,'syncdir'),patch.object(m.old,'directory'):
    with self.assertRaises(OSError):m.apply(spec)
    self.assertTrue(intent.exists());self.assertFalse(done.exists())
 def test_changed_reviewed_plan_refused_before_write(self):
  with patch.object(m,'plan',return_value={'boot_id':'new'}),patch.object(m.old,'store') as store:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):m.apply({'boot_id':'old'})
   store.assert_not_called()
if __name__=='__main__':unittest.main()
