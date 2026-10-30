import importlib.util,pathlib,unittest
from types import SimpleNamespace
from unittest import mock
spec=importlib.util.spec_from_file_location('operator_brake_canary',pathlib.Path(__file__).with_name('nuc_operator_brake_canary.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class CanaryTests(unittest.TestCase):
 def test_fixed_cli_rejects_arbitrary_key_or_operation(self):
  with self.assertRaises(RuntimeError):m.bo_cli('target','launch',m.HUMAN_KEY)
  with self.assertRaises(RuntimeError):m.bo_cli('target','stop','/tmp/other-key')
 def test_negative_peer_program_is_valid_and_secret_not_in_argv(self):
  captured=[]
  def run(*args,**kwargs):captured.append(args);return SimpleNamespace(returncode=0,stdout='HTTP/1.1 403 Forbidden')
  with mock.patch.object(m,'run',side_effect=run),mock.patch.object(m,'system',return_value=SimpleNamespace(stdout='not-found')),mock.patch.object(m,'new_id',return_value='01ARZ3NDEKTSV4RRFFQ69G5FAV'):
   m.frontend_negative('bo','01ARZ3NDEKTSV4RRFFQ69G5FAV',True)
   args=captured[0];code=args[args.index('-c')+1];compile(code,'<negative-peer>','exec')
   self.assertIn('/etc/software-factory-goose/operator-brake.key',code)
   self.assertNotIn('x-brake-key: 070707',str(args))
   with self.assertRaises(RuntimeError):m.frontend_negative('other','target')
if __name__=='__main__':unittest.main()
