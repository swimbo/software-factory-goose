import json,os,subprocess,sys,tempfile,unittest,io
from unittest.mock import patch
from contextlib import redirect_stdout
from nuc_live_goose_service import LiveService
from nuc_run_fence import RunFence
from nuc_structured_file_relay import WRITE_TOOL
from nuc_goose_relay_worker import WRITE_SCHEMA
from trusted_tool_relay import Refused
from test_nuc_live_goose_service import event,wire

ARGS={'files':{'hello.py':'print(1)\n','test_hello.py':'pass\n'}}
class Transport:
 def __init__(self,name='factory__write_files',arguments=None):self.calls=[];self.name=name;self.arguments=arguments or json.dumps(ARGS)
 def send(self,value):
  self.calls.append(value)
  if len(self.calls)==1:return wire(event({'role':'assistant','tool_calls':[{'index':0,'id':'id','type':'function','function':{'name':self.name,'arguments':self.arguments}}]}),event({},'tool_calls'))
  return wire(event({'role':'assistant','content':'done'}),event({},'stop'))

def initial():return {'model':'gpt-4o-mini','messages':[{'role':'system','content':'s'},{'role':'user','content':'u'}],'tools':[WRITE_TOOL],'max_tokens':16384,'stream':True,'stream_options':{'include_usage':True}}
class Tests(unittest.TestCase):
 def test_schema_matches_mcp(self):
  self.assertEqual(WRITE_TOOL['function']['parameters'],WRITE_SCHEMA)
  req={'jsonrpc':'2.0','id':1,'method':'tools/list'}
  env={**os.environ,'SFACTORY_TOOL_MODE':'write_files'}
  p=subprocess.run([sys.executable,'-B','clean-room/tests/fixtures/nuc_goose_relay_worker.py','--mcp'],input=(json.dumps(req)+'\n').encode(),stdout=subprocess.PIPE,env=env,check=True)
  self.assertEqual(json.loads(p.stdout)['result']['tools'][0]['inputSchema'],WRITE_SCHEMA)
 def test_trusted_binding_and_one_execution(self):
  with tempfile.TemporaryDirectory() as root:
   calls=[];t=Transport();s=LiveService(initial=initial(),allowed_models={'allowed'},fence=RunFence(root,'run','task',create=True),transport=t,execute=lambda a:calls.append(a) or {'status':'executed','exit_code':0,'stdout':'Both task files written.','stderr':''},tool_mode='write_files')
   bad={**initial(),'messages':[{'role':'system','content':'changed'},initial()['messages'][1]]}
   with self.assertRaises(Refused):s.request({'type':'inference','body':bad})
   self.assertEqual(t.calls,[])
   s.request({'type':'inference','body':initial()})
   with self.assertRaises(Refused):s.request({'type':'tool','arguments':{'files':{'hello.py':'bad','test_hello.py':'pass'}}})
   self.assertEqual(calls,[])
   # A refused mismatch consumes the in-process phase; no retry is authorized.
   with self.assertRaises(Refused):s.request({'type':'tool','arguments':ARGS})
 def test_success_and_replay(self):
  with tempfile.TemporaryDirectory() as root:
   calls=[];t=Transport();s=LiveService(initial=initial(),allowed_models={'allowed'},fence=RunFence(root,'run','task',create=True),transport=t,execute=lambda a:calls.append(a) or {'status':'executed','exit_code':0,'stdout':'Both task files written.','stderr':''},tool_mode='write_files')
   s.request({'type':'inference','body':initial()});s.request({'type':'tool','arguments':ARGS})
   with self.assertRaises(Refused):s.request({'type':'tool','arguments':ARGS})
   s.request({'type':'inference','body':{**initial(),'messages':initial()['messages']+[s.assistant,s.result]}})
   self.assertEqual(calls,[ARGS]);self.assertEqual(len(t.calls),2)
 def test_continuation_binds_provider_reasoning_and_rejects_forgery(self):
  class ReasoningTransport(Transport):
   def send(self,value):
    if not self.calls:
     self.calls.append(value)
     return wire(event({'role':'assistant','reasoning_content':'trusted','tool_calls':[{'index':0,'id':'id','type':'function','function':{'name':'factory__write_files','arguments':json.dumps(ARGS)}}]}),event({},'tool_calls'))
    return super().send(value)
  with tempfile.TemporaryDirectory() as root:
   t=ReasoningTransport();s=LiveService(initial=initial(),allowed_models={'allowed'},fence=RunFence(root,'run','task',create=True),transport=t,execute=lambda _: {'status':'executed','exit_code':0,'stdout':'Both task files written.','stderr':''},tool_mode='write_files')
   s.request({'type':'inference','body':initial()});s.request({'type':'tool','arguments':ARGS});self.assertEqual(s.assistant['reasoning_content'],'trusted')
   altered={**s.assistant,'reasoning_content':'altered'};missing={k:v for k,v in s.assistant.items() if k!='reasoning_content'};extra={**s.assistant,'untrusted':'x'}
   for forged in (altered,missing,extra):
    with self.assertRaises(Refused):s.request({'type':'inference','body':{**initial(),'messages':initial()['messages']+[forged,s.result]}})
   self.assertEqual(len(t.calls),1)
   s.request({'type':'inference','body':{**initial(),'messages':initial()['messages']+[s.assistant,s.result]}})
 def test_refusal_after_effect_is_quarantined(self):
  with tempfile.TemporaryDirectory() as root:
   calls=[];t=Transport();fence=RunFence(root,'run','task',create=True)
   s=LiveService(initial=initial(),allowed_models={'allowed'},fence=fence,transport=t,execute=lambda a:calls.append(a) or {'status':'refused','reason':'execution_unavailable'},tool_mode='write_files')
   s.request({'type':'inference','body':initial()})
   with self.assertRaises(Refused):s.request({'type':'tool','arguments':ARGS})
   self.assertEqual(len(calls),1)
   self.assertEqual(fence.read()['stage'],'tool_unknown')
   with self.assertRaises(Refused):s.request({'type':'tool','arguments':ARGS})
 def test_stream_diagnostic_never_echoes_untrusted_error(self):
  with tempfile.TemporaryDirectory() as root:
   t=Transport();s=LiveService(initial=initial(),allowed_models={'allowed'},fence=RunFence(root,'run','task',create=True),transport=t,execute=lambda _:None,tool_mode='write_files');out=io.StringIO()
   with patch('nuc_live_goose_service.parse',side_effect=Refused('private request text')),redirect_stdout(out):
    with self.assertRaises(Refused):s.request({'type':'inference','body':initial()})
   self.assertEqual(out.getvalue(),'STREAM_DIAGNOSTIC other\n')
 def test_wrong_tool_and_duplicate_arguments_never_execute(self):
  for t in (Transport(name='factory__shell'),Transport(arguments='{"files":{},"files":{}}')):
   with tempfile.TemporaryDirectory() as root:
    calls=[];s=LiveService(initial=initial(),allowed_models={'allowed'},fence=RunFence(root,'run','task',create=True),transport=t,execute=lambda a:calls.append(a),tool_mode='write_files')
    with self.assertRaises(Refused):s.request({'type':'inference','body':initial()})
    self.assertEqual(calls,[])
