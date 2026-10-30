"""Package import closure, isolated from repository and installed Python paths."""
import ast,os,pathlib,shutil,subprocess,sys,tempfile,unittest

ROOT=pathlib.Path(__file__).resolve().parent
FILES=('nuc_grant_sidecar_install.py','nuc_registry_eval_runtime_per_generation.py','nuc_registry_eval_bootstrap_per_generation.py','nuc_registry_eval_backend_v3.py','nuc_registry_eval_broker.py','nuc_registry_eval_deadline.py','nuc_registry_eval_server_per_generation.py','nuc_registry_eval_client_per_generation.py','nuc_registry_eval_coordinator_per_generation.py','nuc_registry_evaluator.py','nuc_registry_eval_snapshot_provision.py','nuc_registry_eval_provenance.py','nuc_registry_transition_gate.py','nuc_registry_attestation_profiles.py')
CHILD=r'''
import importlib,importlib.abc,importlib.machinery,pathlib,sys
root=pathlib.Path(sys.argv[1]).resolve()
class Restrict(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname.startswith('nuc_'):
   spec=importlib.machinery.PathFinder.find_spec(fullname,[str(root)])
   if spec is None:raise ImportError('missing isolated module: '+fullname)
   return spec
sys.meta_path.insert(0,Restrict());sys.path.insert(0,str(root))
importlib.import_module('nuc_registry_eval_runtime_per_generation')
if sys.path[0]!='/usr/local/libexec/software-factory-goose/evaluator-production':raise RuntimeError('production package does not take precedence')
for name in sys.argv[2:]:importlib.import_module(name[:-3])
for name,module in sys.modules.copy().items():
 if name.startswith('nuc_') and pathlib.Path(module.__file__).resolve().parent!=root:raise RuntimeError('module escaped package')
'''
class PackageClosureTests(unittest.TestCase):
 def test_manifest_sets_and_static_import_closure(self):
  expected=set(FILES)
  for name in ('nuc_registry_eval_runtime_per_generation.py','nuc_registry_eval_service_provision.py'):
   parsed=ast.parse((ROOT/name).read_text());sets=[{x.value for x in n.elts} for n in ast.walk(parsed) if isinstance(n,ast.Set) and all(isinstance(x,ast.Constant) and isinstance(x.value,str) for x in n.elts)]
   self.assertIn(expected,sets)
  for name in FILES:
   parsed=ast.parse((ROOT/name).read_text())
   for n in ast.walk(parsed):
    modules=[a.name for a in n.names] if isinstance(n,ast.Import) else ([n.module] if isinstance(n,ast.ImportFrom) and n.module else [])
    for module in modules:
     if module.startswith('nuc_'):self.assertIn(module.split('.')[0]+'.py',expected, f'{name}: {module}')
  service=(ROOT/'nuc_registry_eval_service_provision.py').read_text();self.assertIn("RUNTIME=PREFIX/'nuc_registry_eval_runtime_per_generation.py'",service);self.assertNotIn('nuc_registry_eval_runtime.py',expected)
 def test_fresh_package_imports_without_repo_fallback(self):
  with tempfile.TemporaryDirectory() as d:
   for name in FILES:shutil.copyfile(ROOT/name,pathlib.Path(d)/name)
   def run():return subprocess.run([sys.executable,'-I','-c',CHILD,d,*FILES],cwd=d,env={'PATH':os.defpath},capture_output=True,timeout=15)
   ok=run();self.assertEqual(ok.returncode,0,ok.stderr.decode())
   (pathlib.Path(d)/'nuc_registry_attestation_profiles.py').unlink()
   missing=run();self.assertNotEqual(missing.returncode,0);self.assertIn(b'missing isolated module: nuc_registry_attestation_profiles',missing.stderr)
if __name__=='__main__':unittest.main()
