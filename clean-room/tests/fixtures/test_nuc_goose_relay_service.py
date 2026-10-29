import json,unittest
from unittest.mock import patch
from nuc_goose_relay_service import SyntheticService,TOOL,ARGS
from trusted_tool_relay import Refused

class ServiceTests(unittest.TestCase):
 def test_tool_and_continuation_must_match_and_cannot_repeat(self):
  calls=[];journal=[]
  def post(url,value):journal.append((url,value));return (200,None) if url.endswith('/initialize') else (200,True)
  def execute(a):calls.append(a);return {'status':'executed','exit_code':0,'stdout':'RELAY_OK','stderr':''}
  body={'model':'gpt-4o-mini','messages':[{'role':'system','content':'s'},{'role':'user','content':'u'}],'tools':[TOOL],'max_tokens':16384,'stream':True,'stream_options':{'include_usage':True}}
  with patch('nuc_goose_relay_service.post',post):
   s=SyntheticService('fixture',execute);s.request({'type':'inference','body':body})
   with self.assertRaises(Refused):s.request({'type':'tool','arguments':{'command':'false'}})
   self.assertEqual(calls,[])
   # A failed invocation has unknown outcome and cannot be retried.
   with self.assertRaises(Refused):s.request({'type':'tool','arguments':ARGS})
   s=SyntheticService('fixture',execute);s.request({'type':'inference','body':body})
   s.request({'type':'tool','arguments':ARGS});self.assertEqual(len(calls),1)
   forged={**body,'messages':body['messages']+[s.assistant,{**s.tool_result,'content':'forged'}]}
   with self.assertRaises(Refused):s.request({'type':'inference','body':forged})
   good={**body,'messages':body['messages']+[s.assistant,s.tool_result]}
   s.request({'type':'inference','body':good})
   with self.assertRaises(Refused):s.request({'type':'inference','body':good})
   self.assertEqual(len(calls),1)

if __name__=='__main__':unittest.main()
