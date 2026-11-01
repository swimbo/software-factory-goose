import ast,hashlib,os,pathlib,shutil,subprocess,sys,tempfile,unittest
from unittest import mock
import nuc_registry_admission_package_install as package
ROOT=pathlib.Path(__file__).parent
HISTORICAL=ROOT.parent/'tests'/'fixtures'/'admission_package_v1'
def source(name):return HISTORICAL/name if name in ('nuc_registry_transition_gate.py','nuc_registry_retirement_coordinator.py') else ROOT/name
class AdmissionPackageTests(unittest.TestCase):
 def test_pins_cover_all_transitive_static_modules(self):
  self.assertEqual(len(package.PINS),21)
  for name,digest in package.PINS.items():
   raw=source(name).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)
   for node in ast.walk(ast.parse(raw)):
    if isinstance(node,ast.Import):modules=[a.name for a in node.names]
    elif isinstance(node,ast.ImportFrom):modules=[node.module or '']
    else:continue
    for module in modules:
     if module.startswith('nuc_'):self.assertIn(module+'.py',package.PINS)
 def test_isolated_copy_imports_and_missing_module_fails(self):
  code="import sys;sys.dont_write_bytecode=True;sys.path.insert(0,sys.argv[1]);import nuc_registry_v5_admission_producer;assert all(not n.startswith('nuc_') or getattr(m,'__file__','').startswith(sys.argv[1]+'/') for n,m in sys.modules.items())"
  with tempfile.TemporaryDirectory() as tmp:
   for name in package.PINS:shutil.copyfile(source(name),pathlib.Path(tmp)/name)
   cmd=[sys.executable,'-I','-c',code,tmp];self.assertEqual(subprocess.run(cmd,capture_output=True,timeout=20).returncode,0)
   (pathlib.Path(tmp)/'nuc_registry_attestation_profiles.py').unlink();self.assertNotEqual(subprocess.run(cmd,capture_output=True,timeout=20).returncode,0)
 def test_source_mutation_rejected(self):
  sources={name:source(name).read_bytes() for name in package.PINS}
  with mock.patch.object(package,'SOURCES',sources),mock.patch.object(package.os,'geteuid',return_value=0),mock.patch.object(package.old,'directory'),mock.patch.object(package.os.path,'lexists',return_value=False):
   self.assertEqual(package.plan()['sources'],package.PINS)
   sources[next(iter(sources))]=b'changed'
   with self.assertRaisesRegex(RuntimeError,'source changed'):package.plan()
if __name__=='__main__':unittest.main()
