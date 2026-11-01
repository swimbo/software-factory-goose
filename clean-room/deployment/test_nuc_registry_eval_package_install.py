import pathlib,tempfile,unittest
from unittest import mock
import nuc_registry_eval_package_install as package
class Package(unittest.TestCase):
 def setUp(self):
  root=pathlib.Path(__file__).parent;historical=root.parent/'tests'/'fixtures'/'admission_package_v1'
  self.sources={n:((historical/n) if n=='nuc_registry_transition_gate.py' else (root/n)).read_bytes() for n in package.PINS}
 def test_pins_match_reviewed_complete_sources(self):
  self.assertGreater(package.validate_sources(self.sources),0)
  import nuc_registry_eval_service_provision as provision
  self.assertEqual(package.DEST,provision.PREFIX)
 def test_changed_missing_extra_source_denied(self):
  for values in ({**self.sources,next(iter(self.sources)):b'changed'},{k:v for i,(k,v) in enumerate(self.sources.items()) if i},{**self.sources,'other.py':b'extra'}):
   with self.assertRaises(RuntimeError):package.validate_sources(values)
 def test_install_writes_only_code_and_receipts(self):
  with tempfile.TemporaryDirectory() as td:
   root=pathlib.Path(td);dest=root/'package';manifest=root/'manifest';start=root/'start';done=root/'done'
   expected={'files':package.PINS}
   def store(path,raw,mode):
    with path.open('xb') as f:f.write(raw)
    path.chmod(mode)
   with mock.patch.multiple(package,DEST=dest,MANIFEST=manifest,START=start,DONE=done,SOURCES=self.sources),mock.patch.object(package,'plan',return_value=expected),mock.patch.object(package.old,'store',side_effect=store),mock.patch.object(package.old,'directory'),mock.patch.object(package.old,'syncdir'),mock.patch.object(package.old,'noacl'),mock.patch.object(package.os,'chown'),mock.patch.object(package.os,'fchown'):
    result=package.apply(expected)
   self.assertEqual(result,{'schema':1,'installed':True,'activated':False,'evaluated':False})
   self.assertEqual(set(p.name for p in dest.iterdir()),set(package.PINS))
   for name,raw in self.sources.items():self.assertEqual((dest/name).read_bytes(),raw);self.assertEqual((dest/name).stat().st_mode&0o777,0o440)
   self.assertTrue(manifest.exists() and start.exists() and done.exists())
