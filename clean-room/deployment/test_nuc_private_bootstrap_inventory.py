import importlib.util,os,pathlib,tempfile,unittest
from unittest import mock
p=pathlib.Path(__file__).with_name('nuc_private_bootstrap_inventory.py')
spec=importlib.util.spec_from_file_location('inventory',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_nonroot_and_wrong_command_refused(self):
  with mock.patch.object(m.os,'geteuid',return_value=1000):
   with self.assertRaises(RuntimeError):m.main()
  with mock.patch.object(m.os,'geteuid',return_value=0),mock.patch.object(m.sys,'argv',['inventory','--repair']):
   with self.assertRaises(RuntimeError):m.main()
 def test_metadata_never_follows_symlink(self):
  with tempfile.TemporaryDirectory() as temp:
   root=pathlib.Path(temp);target=root/'target';target.write_text('value');link=root/'link';os.symlink(target,link)
   entry=m.metadata(link,digest=True);self.assertEqual(entry['kind'],'other');self.assertNotIn('sha256',entry)
   self.assertEqual(m.metadata(root/'absent'),{'exists':False})
 def test_command_output_is_bounded(self):
  result=mock.Mock(returncode=0,stdout=b'a'*20,stderr=b'')
  with mock.patch.object(m.subprocess,'run',return_value=result):
   with self.assertRaisesRegex(RuntimeError,'limit'):m.command(['/bin/true'],limit=10)
if __name__=='__main__':unittest.main()
