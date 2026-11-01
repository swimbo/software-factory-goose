import subprocess,unittest
from unittest.mock import patch
import nuc_registry_v5_registration as m
class Registration(unittest.TestCase):
 def test_missing_drain_producer_denies(self):
  with patch.object(m,'DRAIN_PRODUCER_SHA',None):
   with self.assertRaisesRegex(RuntimeError,'drain producer'):m.binding({})
 def test_timeout_retains_start_without_completion(self):
  records=[];intent={'transition_id':'01M66XF6HPWC3NXMAFDHKHDSP7'};approved={'test':'binding'}
  with patch.object(m,'binding',return_value=approved),patch.object(m.gate,'_store_history',side_effect=lambda _,name,data:records.append(name)),patch.object(m.subprocess,'run',side_effect=subprocess.TimeoutExpired('systemctl',45)):
   with self.assertRaises(subprocess.TimeoutExpired):m.run(intent,approved)
  self.assertEqual(records,[intent['transition_id']+'.registration-started.json'])
 def test_mismatched_binding_never_starts(self):
  with patch.object(m,'binding',return_value={'different':True}),patch.object(m.gate,'_store_history') as store,patch.object(m.subprocess,'run') as run:
   with self.assertRaises(RuntimeError):m.run({'transition_id':'01M66XF6HPWC3NXMAFDHKHDSP7'},{'different':False})
   store.assert_not_called();run.assert_not_called()
if __name__=='__main__':unittest.main()
