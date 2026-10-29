#!/usr/bin/env python3
"""Unregistered task-scoped host gate. Trusted bootstrap and sole caller required."""
import base64,json,threading
from nuc_bifrost_stream import parse,no_duplicates
from trusted_tool_relay import ToolRelay,Refused,valid_response
from nuc_run_fence import Denied
from nuc_bifrost_live_transport import TransportRefused
from nuc_goose_relay_service import TOOL
from nuc_structured_file_relay import FileRelay,WRITE_TOOL

class LiveService:
 def __init__(self,*,initial,allowed_models,fence,transport,execute,initial_validator=None,tool_mode="shell",diagnostics=False,continuation_capture=None):
  if tool_mode not in ("shell","write_files"):raise Refused("scope unavailable")
  expected_tool=TOOL if tool_mode=="shell" else WRITE_TOOL
  if (not isinstance(initial,dict) or set(initial)!={'model','messages','tools','max_tokens','stream','stream_options'} or initial['model']!='gpt-4o-mini' or initial['tools']!=[expected_tool] or initial['max_tokens']!=16384 or initial['stream'] is not True or initial['stream_options']!={'include_usage':True} or not isinstance(initial['messages'],list) or len(initial['messages'])!=2 or not allowed_models or any(not isinstance(m,str) or not 0<len(m)<=256 for m in allowed_models)):raise Refused('scope unavailable')
  self.initial=json.loads(json.dumps(initial));self.allowed_models=frozenset(allowed_models);self.fence=fence;self.transport=transport;self.execute=execute
  self.diagnostics=diagnostics;self.continuation_capture=continuation_capture;self.tool_mode=tool_mode;self.tool_name='factory__'+tool_mode;self.observed=[];self.initial_validator=initial_validator;self.phase='initial';self.lock=threading.Lock();self.assistant=None;self.result=None;self.tool_id=None;self.tool_arguments=None;self.tool=(ToolRelay if tool_mode=="shell" else FileRelay)(self._execute)
 def _execute(self,arguments):
  self.fence.begin_tool(self.tool_id,arguments)
  result=self.execute(arguments)
  if not valid_response(result) or (self.tool_mode=='write_files' and result!={'status':'executed','exit_code':0,'stdout':'Both task files written.','stderr':''}):raise Refused('tool result unavailable')
  raw=json.dumps(result,separators=(',',':'),ensure_ascii=False).encode()
  if len(raw)>65536:raise Refused('tool result unavailable')
  self.fence.record_tool_result(self.tool_id,raw)
  return result
 def request(self,value):
  with self.lock:
   try:return self._request(value)
   except Denied:raise Refused('authority unavailable') from None
 def _request(self,value):
  if self.diagnostics:print('RELAY_DIAGNOSTIC phase='+self.phase+' request='+str(value.get('type') if isinstance(value,dict) and value.get('type') in ('inference','tool') else 'invalid'),flush=True)
  if not isinstance(value,dict) or value.get('type') not in ('inference','tool'):raise Refused('invalid request')
  if value['type']=='tool':
   if set(value)!={'type','arguments'} or self.phase!='tool_ready':raise Refused('tool unavailable')
   self.phase='tool_unknown';result=self.tool.call(self.tool_id,value['arguments']);self.result=result;self.phase='continuation';return result['content']
  if set(value)!={'type','body'} or not isinstance(value['body'],dict):raise Refused('invalid inference')
  body=value['body']
  if self.phase=='initial':
   if (self.initial_validator and not self.initial_validator(body)) or (not self.initial_validator and body!=self.initial):raise Refused('unattested initial request')
   self.initial=json.loads(json.dumps(body));turn=0
  elif self.phase=='continuation':
   if self.continuation_capture is not None:self.continuation_capture(body)
   expected={**self.initial,'messages':self.initial['messages']+[self.assistant,self.result]}
   try:
    candidate=json.loads(json.dumps(body));arguments=candidate['messages'][2]['tool_calls'][0]['function']['arguments']
    if not isinstance(arguments,str) or json.loads(arguments,object_pairs_hook=no_duplicates)!=self.tool_arguments:
     if self.diagnostics:print('CONTINUATION_DIAGNOSTIC arguments_mismatch',flush=True)
     raise Refused('unattested continuation')
    candidate['messages'][2]['tool_calls'][0]['function']['arguments']=self.assistant['tool_calls'][0]['function']['arguments']
   except (KeyError,IndexError,TypeError,ValueError):
    if self.diagnostics:print('CONTINUATION_DIAGNOSTIC structure_invalid',flush=True)
    raise Refused('unattested continuation') from None
   if candidate!=expected:
    if self.diagnostics:
     a=candidate.get('messages',[]);b=expected['messages']
     if len(a)>2 and isinstance(a[2],dict):
      x=a[2];y=b[2];known={'role','content','tool_calls','reasoning','reasoning_content','reasoning_details'}
      print('ASSISTANT_DIAGNOSTIC key_flags='+','.join(k for k in sorted(known) if k in x)+' extra_key_count='+str(len(set(x)-known))+' role_match='+str(x.get('role')==y.get('role'))+' content_match='+str(x.get('content')==y.get('content'))+' tool_calls_match='+str(x.get('tool_calls')==y.get('tool_calls')),flush=True)
     print('CONTINUATION_DIAGNOSTIC top_keys_match='+str(set(candidate)==set(expected))+' message_count_match='+str(len(a)==len(b))+' initial_messages_match='+str(a[:2]==b[:2])+' assistant_match='+str(len(a)>2 and a[2]==b[2])+' tool_result_match='+str(len(a)>3 and a[3]==b[3])+' other_fields_match='+str({k:v for k,v in candidate.items() if k!='messages'}=={k:v for k,v in expected.items() if k!='messages'}),flush=True)
    raise Refused('unattested continuation')
   turn=1
  else:raise Refused('dispatch unavailable')
  routed={**body,'model':'auto'};request=json.dumps(routed,separators=(',',':'),ensure_ascii=False).encode()
  self.phase='inference_unknown';call=self.fence.begin_inference(turn,request)
  try:response=self.transport.send(routed)
  except TransportRefused as error:
   # Transport messages contain only fixed categories and sanitized HTTP metadata.
   print('PROVIDER_DIAGNOSTIC '+str(error),flush=True);raise Refused('provider unavailable') from None
  try:parsed=parse(response,self.allowed_models,self.tool_name)
  except Refused as error:
   allowed={'invalid stream','incomplete stream','route unavailable','invalid event','invalid completion','invalid choices','unreviewed response identity','changed response identity','invalid choice','event after finish','invalid finish','unsupported delta','invalid role','invalid reasoning','invalid reasoning details','reasoning too large','invalid content','unsupported tools','invalid tool','invalid tool ID','invalid tool type','invalid function','invalid tool call','invalid arguments','duplicate JSON key'}
   category=str(error) if str(error) in allowed else 'other'
   print('STREAM_DIAGNOSTIC '+category,flush=True);raise
  self.observed.append({'model':parsed['model'],'reasoning_fields':parsed['reasoning_fields'],'reasoning_bytes':parsed['reasoning_bytes']})
  if turn==0:
   if parsed['kind']!='tool':raise Refused('tool call required')
   self.tool_id=parsed['id'];arguments=parsed['arguments'];self.tool_arguments=arguments
   self.tool.record_provider_call(self.tool_id,arguments)
   self.fence.record_tool(call,response,self.tool_id,arguments)
   self.assistant={'role':'assistant','content':None,'tool_calls':[{'id':self.tool_id,'type':'function','function':{'name':self.tool_name,'arguments':parsed['arguments_text']}}]}
   if 'reasoning_content' in parsed:self.assistant['reasoning_content']=parsed['reasoning_content']
   self.phase='tool_ready'
  else:
   if parsed['kind']!='final':raise Refused('final response required')
   self.fence.record_final(call,response);self.phase='done'
  return base64.b64encode(response).decode()
