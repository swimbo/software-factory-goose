import json,unittest
from nuc_bifrost_stream import parse
from trusted_tool_relay import Refused

def event(delta,finish=None):return 'data: '+json.dumps({'id':'resp1','model':'allowed','object':'chat.completion.chunk','choices':[{'index':0,'delta':delta,'finish_reason':finish}]})+'\n\n'
def wire(*parts):return (''.join(parts)+'data: [DONE]\n\n').encode()
class StreamTests(unittest.TestCase):
 def test_fragmented_tool(self):
  raw=wire(event({'role':'assistant','tool_calls':[{'index':0,'id':'t1','type':'function','function':{'name':'factory__','arguments':'{"command":'}}]}),event({'tool_calls':[{'index':0,'function':{'name':'shell','arguments':'"pwd"}'}}]}),event({},'tool_calls'))
  self.assertEqual(parse(raw,{'allowed'}),{'kind':'tool','id':'t1','arguments':{'command':'pwd'},'arguments_text':'{"command":"pwd"}','model':'allowed','reasoning_fields':[],'reasoning_bytes':0})
 def test_identity_and_reasoning_mismatch_denied(self):
  good=event({'role':'assistant'}); changed=good.replace('resp1','other'); missing=good.replace('\"id\": \"resp1\", ', ''); wrong=good.replace('allowed','other')
  for raw in [wire(good,changed,event({},'stop')),wire(missing,event({},'stop')),wire(wrong,event({},'stop')),wire(event({'reasoning':{'secret':'x'}}),event({},'stop'))]:
   with self.assertRaises(Refused):parse(raw,{'allowed'})
 def test_repeated_same_id_and_name_and_empty_calls(self):
  first={'index':0,'id':'t1','type':'function','function':{'name':'factory__shell','arguments':'{"command":'}}
  again={'index':0,'id':'t1','type':'function','function':{'name':'factory__shell','arguments':'"pwd"}'}}
  result=parse(wire(event({'tool_calls':None}),event({'tool_calls':[]}),event({'tool_calls':[first]}),event({'tool_calls':[again]}),event({},'tool_calls')) ,{'allowed'})
  self.assertEqual(result['arguments'],{'command':'pwd'})
 def test_changed_tool_id_and_multiple_tools_remain_denied(self):
  first={'index':0,'id':'t1','type':'function','function':{'name':'factory__shell','arguments':'{}'}}
  for delta in ({'tool_calls':[{'index':0,'id':'other'}]},{'tool_calls':[{'index':0,'function':{'name':'other'}}]},{'tool_calls':[first,first]}):
   with self.assertRaises(Refused):parse(wire(event({'tool_calls':[first]}),event(delta),event({},'tool_calls')) ,{'allowed'})
 def test_bounded_reasoning_details_and_invalid_shapes(self):
  detail={'index':0,'type':'reasoning.text','text':'x'}
  result=parse(wire(event({'reasoning_details':[detail]}),event({},'stop')) ,{'allowed'})
  self.assertEqual(result['reasoning_bytes'],1);self.assertIn('reasoning_details',result['reasoning_fields'])
  cases=[None,[{**detail,'index':True}],[{**detail,'index':1}],[{**detail,'type':'other'}],[{**detail,'extra':'x'}],[detail,detail],[{**detail,'text':'x'*262145}]]
  for value in cases:
   with self.assertRaises(Refused):parse(wire(event({'reasoning_details':value}),event({},'stop')) ,{'allowed'})
 def test_reasoning_prefers_content_per_delta_and_falls_back(self):
  part={'index':0,'id':'t1','type':'function','function':{'name':'factory__shell','arguments':'{"command":"pwd"}'}}
  result=parse(wire(event({'reasoning':'wrong','reasoning_content':'chosen','reasoning_details':[{'index':0,'type':'reasoning.text','text':'different'}]}),event({'reasoning':'fallback','reasoning_content':''}),event({'tool_calls':[part]}),event({},'tool_calls')) ,{'allowed'})
  self.assertEqual(result['reasoning_content'],'chosenfallback')
 def test_comments_preserve_data_and_reject_other_sse_fields(self):
  raw=wire(': heartbeat\n'+event({'role':'assistant'}),event({},'stop'))
  self.assertEqual(parse(raw,{'allowed'})['kind'],'final')
  for prefix in ('event: custom\n', ':'+'x'*8192+'\n'):
   with self.assertRaises(Refused):parse(wire(prefix+event({'role':'assistant'}),event({},'stop')) ,{'allowed'})
 def test_bad_or_ambiguous_stream_denied(self):
  for raw in [wire(event({},'stop'))[:-4],wire(event({'tool_calls':[{'index':1}]},'tool_calls')),wire(event({'content':'x'},'tool_calls')),wire(event({},'stop'),event({'content':'later'}))]:
   with self.assertRaises(Refused):parse(raw,{'allowed'})
if __name__=='__main__':unittest.main()
