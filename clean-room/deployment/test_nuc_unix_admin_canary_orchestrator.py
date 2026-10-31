import pathlib,sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent/'tests'/'fixtures'))
import nuc_unix_admin_canary_orchestrator as m
class Orchestration(unittest.TestCase):
 def test_failure_stops_before_any_later_stage(self):
  calls=[];approved={'schema':1}
  def stage(module,role=None):
   calls.append(module.__name__)
   if module is m.epoch:raise RuntimeError('epoch unknown')
  with patch.object(m,'plan',return_value=approved),patch.object(m.old,'store') as store,patch.object(m,'stage',side_effect=stage):
   with self.assertRaisesRegex(RuntimeError,'epoch unknown'):m.apply(approved)
  self.assertEqual(calls,[m.snapshot_install.__name__,m.probe_install.__name__,m.epoch.__name__]);self.assertEqual(store.call_count,1)
if __name__=='__main__':unittest.main()
