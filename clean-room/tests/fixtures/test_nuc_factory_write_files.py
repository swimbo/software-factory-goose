import os,pathlib,tempfile,unittest
from nuc_factory_write_files import execute
class Tests(unittest.TestCase):
 def test_bounded_exact_names_and_no_overwrite(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);req={'files':{'hello.py':'print(1)\n','test_hello.py':'print(2)\n'}}
   self.assertEqual(execute(req,d)['status'],'executed');self.assertEqual((root/'hello.py').read_text(),'print(1)\n')
   self.assertEqual(execute(req,d)['status'],'refused');self.assertEqual((root/'hello.py').read_text(),'print(1)\n')
 def test_rolls_back_first_file_when_second_exists(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);(root/'test_hello.py').write_text('existing')
   result=execute({'files':{'hello.py':'new','test_hello.py':'bad'}},d)
   self.assertEqual(result['status'],'refused');self.assertFalse((root/'hello.py').exists());self.assertEqual((root/'test_hello.py').read_text(),'existing')
 def test_rejects_unapproved_or_large_values(self):
  with tempfile.TemporaryDirectory() as d:
   for req in [{'files':{'../x':'x'}},{'files':{'hello.py':'x'*32769,'test_hello.py':'y'}},{'files':{'hello.py':'x\x00','test_hello.py':'y'}}]:self.assertEqual(execute(req,d)['reason'],'invalid_request')
   self.assertEqual(os.listdir(d),[])
if __name__=='__main__':unittest.main()
