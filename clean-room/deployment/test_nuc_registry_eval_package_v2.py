import hashlib,os,pathlib,shutil,subprocess,sys,tempfile,unittest
import nuc_registry_eval_package_v2_install as install
from test_nuc_registry_eval_package_closure import CHILD
ROOT=pathlib.Path(__file__).parent/'evaluator_production_v2'
class PackageV2(unittest.TestCase):
 def test_pinned_payload_and_isolated_imports(self):
  sources={n:(ROOT/n).read_bytes() for n in install.PINS}
  self.assertGreater(install.validate_sources(sources),0)
  with tempfile.TemporaryDirectory() as d:
   for name,raw in sources.items():pathlib.Path(d,name).write_bytes(raw)
   code=CHILD.replace('/evaluator-production\'', '/evaluator-production-v2\'')
   result=subprocess.run([sys.executable,'-I','-c',code,d,*sources],cwd=d,env={'PATH':os.defpath},capture_output=True,timeout=15)
   self.assertEqual(result.returncode,0,result.stderr.decode())
   pathlib.Path(d,'nuc_registry_attestation_profiles.py').unlink()
   result=subprocess.run([sys.executable,'-I','-c',code,d,*sources],cwd=d,env={'PATH':os.defpath},capture_output=True,timeout=15)
   self.assertNotEqual(result.returncode,0)
 def test_package_and_socket_permissions_are_separate(self):
  import ast
  for name in ('nuc_registry_eval_bootstrap_per_generation.py','nuc_registry_eval_coordinator_per_generation.py'):
   values=[n.value for n in ast.walk(ast.parse((ROOT/name).read_text())) if isinstance(n,ast.Constant)]
   self.assertIn(0o750,values);self.assertNotIn(0o710,values)
  client=(ROOT/'nuc_registry_eval_client_per_generation.py').read_text()
  self.assertIn("!=(0,2002,0o750):raise EvaluationUnavailable('attestation directory unavailable')",client)
  self.assertIn("!=(0,2002,0o710):raise EvaluationUnavailable('socket parent unavailable')",client)
  self.assertEqual(install.DEST.name,'evaluator-production-v2');self.assertEqual(install.MANIFEST.name,'evaluator-package-v2.json')
  import nuc_registry_eval_service_v2_provision as service
  self.assertEqual(service.PREFIX,install.DEST)
  _,socket,_=service.bodies('01M66XF6HPBETAJ5V0G45TM8NQ');self.assertIn(b'/run/software-factory-goose/evaluator-production/',socket)
