import contextlib,os,pathlib,tempfile,unittest
from unittest.mock import patch
import nuc_callback_package_upgrade as m
class Upgrade(unittest.TestCase):
 def test_changed_plan_refuses_before_intent(self):
  with patch.object(m,'generations',return_value=['x']),patch.object(m,'locks',return_value=contextlib.nullcontext()),patch.object(m,'snapshot',return_value={'generations':['x'],'boot_id':'new'}),patch.object(m.old,'store') as store:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):m.apply({'generations':['x'],'boot_id':'old'})
   store.assert_not_called()
 def test_atomic_temp_collision_preserves_original(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'fixed';p.write_bytes(b'old');(p.parent/'.fixed.callback-v2.tmp').write_bytes(b'other')
   with self.assertRaises(FileExistsError):m.atomic(p,b'new',0o600)
   self.assertEqual(p.read_bytes(),b'old')
 def test_active_launcher_refused(self):
  def ctl(*args):
   if args[0]=='list-units':return 'sfactory-intloop-launch-01m65neh5t767h8q5x71ttfr5s.service loaded active running fixture'
   return {'MainPID':'123','ActiveState':'active','Job':'','ControlGroup':'/active'}[args[args.index('-p')+1]]
  with patch.object(m.old,'ctl',side_effect=ctl):
   with self.assertRaisesRegex(RuntimeError,'launcher still active'):m.quiescent()
if __name__=='__main__':unittest.main()
