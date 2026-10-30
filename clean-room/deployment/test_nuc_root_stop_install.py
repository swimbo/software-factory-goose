#!/usr/bin/env python3
import importlib.util,pathlib,tempfile,unittest
from types import SimpleNamespace
from unittest.mock import patch
p=pathlib.Path(__file__).with_name('nuc_root_stop_install.py');spec=importlib.util.spec_from_file_location('root_stop_install',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_plan_refuses_existing_target_or_prior_intent_without_mutation(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); targets=tuple(root/str(i) for i in range(5));intent=root/'intent';receipt=root/'receipt'
   patches=[patch.object(m,'TARGETS',targets),patch.object(m,'INTENT',intent),patch.object(m,'RECEIPT',receipt),patch.object(m,'trusted_dir'),patch.object(m,'read_binary',return_value=b'fixed'),patch.object(m.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=2003,pw_gid=2003)),patch.object(m.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=2003)),patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='not-found\n')),patch.object(pathlib.Path,'read_text',return_value='boot\n')]
   for p in patches:p.start();self.addCleanup(p.stop)
   plan,_=m.plan();self.assertEqual(plan['activation'],'none')
   targets[0].write_text('preserve')
   with self.assertRaises(RuntimeError):m.plan()
   self.assertEqual(targets[0].read_bytes(),b'preserve');targets[0].unlink()
   intent.write_bytes(b'unknown partial')
   with self.assertRaises(RuntimeError):m.plan()
   self.assertEqual(intent.read_bytes(),b'unknown partial')
 def test_plan_digest_binds_unit_content_and_boot(self):
  a={'boot_id':'one','units':{'socket':'a'}};b={'boot_id':'one','units':{'socket':'b'}};c={'boot_id':'two','units':{'socket':'a'}}
  self.assertNotEqual(m.digest(a),m.digest(b));self.assertNotEqual(m.digest(a),m.digest(c))
if __name__=='__main__':unittest.main()
