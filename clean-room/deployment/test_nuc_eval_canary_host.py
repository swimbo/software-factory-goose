import unittest
from unittest.mock import patch
import nuc_eval_canary_service_install as service
import nuc_eval_canary_attest as attest
import nuc_eval_canary_backend_upgrade as upgrade
class CanaryHost(unittest.TestCase):
 def test_all_stale_plans_refuse_before_mutation(self):
  for module in (service,attest,upgrade):
   with self.subTest(module=module.__name__),patch.object(module,'plan',return_value={'v':1}),patch.object(module.old,'store') as store:
    with self.assertRaises(RuntimeError):module.apply({'v':2})
    store.assert_not_called()
 def test_fixture_unit_pins_socket_peer_and_capability_boundary(self):
  self.assertIn(b'SocketGroup=sfgoose-eval',service.SOCKET);self.assertIn(b'SocketMode=0660',service.SOCKET);self.assertIn(b'CapabilityBoundingSet=\n',service.SERVICE);self.assertIn(b'NoNewPrivileges=yes',service.SERVICE);self.assertIn(b'eval_canary_runtime.py',service.SERVICE)
if __name__=='__main__':unittest.main()
