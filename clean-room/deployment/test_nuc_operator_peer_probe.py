import importlib.util,pathlib,unittest
from unittest.mock import patch
p=pathlib.Path(__file__).with_name('nuc_operator_peer_probe.py'); spec=importlib.util.spec_from_file_location('probe',p); m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ProbeTests(unittest.TestCase):
 def test_public_client_and_side_effect_free_contract(self):
  compile(m.CLIENT,'public-client','exec')
  self.assertIn("b'09'*32",m.CLIENT)
  self.assertNotIn('brake.key',m.CLIENT)
  self.assertIn('public-brake-probe.sock',m.CLIENT)
 def test_changed_plan_refused_before_creating_anything(self):
  with patch.object(m,'make_plan',return_value={'reviewed':1}),patch.object(m,'write_new') as write:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):m.apply(m.Host(),{'reviewed':2})
   write.assert_not_called()
if __name__=='__main__':unittest.main()
