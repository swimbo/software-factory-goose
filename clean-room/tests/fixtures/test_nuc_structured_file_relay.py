import unittest
from nuc_structured_file_relay import FileRelay
from trusted_tool_relay import Refused
class Tests(unittest.TestCase):
 def test_exact_files_and_single_use(self):
  calls=[];args={'files':{'hello.py':'x','test_hello.py':'y'}}
  relay=FileRelay(lambda a:calls.append(a) or {'status':'executed','exit_code':0,'stdout':'ok','stderr':''})
  relay.record_provider_call('id',args)
  with self.assertRaises(Refused):relay.call('id',{'files':{'hello.py':'forged','test_hello.py':'y'}})
  relay.call('id',args);self.assertEqual(len(calls),1)
  with self.assertRaises(Refused):relay.call('id',args)
 def test_unapproved_file_rejected(self):
  relay=FileRelay(lambda _:None)
  for arg in ({'files':{'../outside':'x'}},{'files':{'hello.py':'x','test_hello.py':'y','extra':'z'}}):
   with self.assertRaises(Refused):relay.record_provider_call('id',arg)
if __name__=='__main__':unittest.main()
