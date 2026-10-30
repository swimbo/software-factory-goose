import unittest
from unittest import mock
import nuc_callback_listener_canary as m
class ListenerCanary(unittest.TestCase):
 def test_stale_plan_denies_before_effect(self):
  with mock.patch.object(m,'plan',return_value={'x':1}),mock.patch.object(m.old,'store') as store,mock.patch.object(m.os,'mkdir') as mkdir:
   with self.assertRaises(RuntimeError):m.apply({'x':2})
   store.assert_not_called();mkdir.assert_not_called()
 def test_service_code_invokes_actual_validator(self):
  self.assertIn('validate_listener(3,',m.PROBE_BYTES.decode());self.assertIn("LISTEN_FDNAMES",m.PROBE_BYTES.decode());compile(m.PROBE_BYTES.decode(),'<listener-canary>','exec')
if __name__=='__main__':unittest.main()
