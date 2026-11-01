import hashlib,pathlib,unittest
import nuc_eval_canary2_provision as p
class FreshFixture(unittest.TestCase):
 def test_fresh_ids_and_exact_source_pins(self):
  root=pathlib.Path(__file__).parent/'evaluator_canary2';ids=[p.target(i) for i in range(1,23)]
  self.assertEqual(len(set(ids)),22);self.assertNotIn(p.G,ids);self.assertEqual(len(p.PINS),10)
  for name,digest in p.PINS.items():self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),digest)
 def test_separate_paths_and_stage_logging(self):
  root=pathlib.Path(__file__).parent/'evaluator_canary2';self.assertIn('evaluator2',str(p.DEST));self.assertIn('canary2',str(p.CAT));self.assertIn("evaluator backend unavailable stage=",(root/'nuc_registry_eval_backend.py').read_text());self.assertNotEqual(p.G,'01M65RMR3F04YB1B016EBBSXGK')
if __name__=='__main__':unittest.main()

class FreshHostGates(unittest.TestCase):
 def test_fresh_units_and_fixed_separate_identity(self):
  import nuc_eval_canary2_service_install as s
  self.assertIn(b'SocketGroup=sfgoose-eval',s.SOCKET)
  self.assertIn(b'/evaluator2/broker.sock',s.SOCKET)
  self.assertIn(b'CapabilityBoundingSet=\n',s.SERVICE)
  self.assertIn(b'nuc_registry_eval_canary_runtime.py',s.SERVICE)
  self.assertEqual(s.G,p.G)
 def test_all_fresh_host_helpers_compile(self):
  root=pathlib.Path(__file__).parent
  for name in ('nuc_eval_canary2_provision.py','nuc_eval_canary2_service_install.py','nuc_eval_canary2_activate.py','nuc_eval_canary2_attest.py','nuc_eval_canary2_run.py'):
   with self.subTest(name=name):compile((root/name).read_bytes(),name,'exec')
