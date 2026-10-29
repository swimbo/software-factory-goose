import json,tempfile,unittest
from nuc_live_goose_service import LiveService
from nuc_run_fence import RunFence
from trusted_tool_relay import Refused
from nuc_goose_relay_service import TOOL

def event(delta,reason=None):return 'data: '+json.dumps({'id':'r1','model':'allowed','object':'chat.completion.chunk','choices':[{'index':0,'delta':delta,'finish_reason':reason}]})+'\n\n'
def wire(*x):return (''.join(x)+'data: [DONE]\n\n').encode()
class Transport:
 def __init__(self):self.calls=[]
 def send(self,value):
  self.calls.append(value)
  if len(self.calls)==1:return wire(event({'role':'assistant','tool_calls':[{'index':0,'id':'id','type':'function','function':{'name':'factory__shell','arguments':'{"command":"pwd"}'}}]}),event({},'tool_calls'))
  return wire(event({'role':'assistant','content':'done'}),event({},'stop'))
class Tests(unittest.TestCase):
 def test_only_trusted_initial_and_exact_host_transcript_dispatched_once(self):
  with tempfile.TemporaryDirectory() as root:
   fence=RunFence(root,'run','task',create=True);transport=Transport();calls=[]
   initial={'model':'gpt-4o-mini','messages':[{'role':'system','content':'s'},{'role':'user','content':'u'}],'tools':[TOOL],'max_tokens':16384,'stream':True,'stream_options':{'include_usage':True}}
   service=LiveService(initial=initial,allowed_models={'allowed'},fence=fence,transport=transport,execute=lambda a:calls.append(a) or {'status':'executed','exit_code':0,'stdout':'ok','stderr':''})
   for bad in [{**initial,'messages':[{'role':'system','content':'forged'},initial['messages'][1]]},{**initial,'messages':[initial['messages'][0],{'role':'user','content':'forged'}]}]:
    with self.assertRaises(Refused):service.request({'type':'inference','body':bad})
   self.assertEqual(len(transport.calls),0)
   service.request({'type':'inference','body':initial});service.request({'type':'tool','arguments':{'command':'pwd'}})
   for changed in [{**service.assistant,'content':'forged'},{**service.assistant,'tool_calls':[]}]:
    with self.assertRaises(Refused):service.request({'type':'inference','body':{**initial,'messages':initial['messages']+[changed,service.result]}})
   with self.assertRaises(Refused):service.request({'type':'inference','body':{**initial,'messages':initial['messages']+[service.assistant,{**service.result,'content':'forged'}]}})
   self.assertEqual(len(transport.calls),1)
   equivalent=json.loads(json.dumps(service.assistant));equivalent['tool_calls'][0]['function']['arguments']='{ \"command\" : \"pwd\" }'
   service.request({'type':'inference','body':{**initial,'messages':initial['messages']+[equivalent,service.result]}})
   with self.assertRaises(Refused):service.request({'type':'inference','body':initial})
   self.assertEqual(len(transport.calls),2);self.assertEqual(len(calls),1)
 def test_ambiguous_send_cannot_be_reissued_after_reopen(self):
  with tempfile.TemporaryDirectory() as root:
   fence=RunFence(root,'run','task',create=True);initial={'model':'gpt-4o-mini','messages':[{'role':'system','content':'s'},{'role':'user','content':'u'}],'tools':[TOOL],'max_tokens':16384,'stream':True,'stream_options':{'include_usage':True}}
   class Broken:
    def send(self,_):raise RuntimeError('unknown')
   service=LiveService(initial=initial,allowed_models={'allowed'},fence=fence,transport=Broken(),execute=lambda _:None)
   with self.assertRaises(RuntimeError):service.request({'type':'inference','body':initial})
   restarted=LiveService(initial=initial,allowed_models={'allowed'},fence=RunFence(root,'run','task'),transport=Broken(),execute=lambda _:None)
   with self.assertRaises(Refused):restarted.request({'type':'inference','body':initial})
if __name__=='__main__':unittest.main()
