#!/usr/bin/env python3
"""Synthetic two-turn Goose service; unregistered disposable journal only."""
import base64,json,threading,time
from trusted_tool_relay import ToolRelay,Refused
from nuc_trusted_tool_relay import post

TOOL={'type':'function','function':{'name':'factory__shell','description':'Run a policy-checked command in the trusted task directory; output is bounded and masked.','parameters':{'type':'object','properties':{'command':{'type':'string','maxLength':16384}},'required':['command'],'additionalProperties':False}}}
ARGS={'command':'printf RELAY_OK'}
def encoded(value):return list(json.dumps(value,separators=(',',':')).encode())

def sse(delta,finish):
    chunks=[{'id':'offline','object':'chat.completion.chunk','created':1,'model':'gpt-4o-mini','choices':[{'index':0,'delta':delta,'finish_reason':None}]}, {'id':'offline','object':'chat.completion.chunk','created':1,'model':'gpt-4o-mini','choices':[{'index':0,'delta':{},'finish_reason':finish}],'usage':{'prompt_tokens':10,'completion_tokens':4,'total_tokens':14}}]
    return (''.join('data: '+json.dumps(c)+'\n\n' for c in chunks)+'data: [DONE]\n\n').encode()

class SyntheticService:
    def __init__(self,journal,execute):
        self.journal=journal;self.tool=ToolRelay(execute);self.phase='initial';self.initial=None;self.assistant=None;self.tool_result=None;self.lock=threading.Lock()
    def request(self,value):
        with self.lock:return self._request(value)
    def _request(self,value):
        if not isinstance(value,dict) or value.get('type') not in ('inference','tool'):raise Refused('invalid request')
        if value['type']=='tool':
            if set(value)!={'type','arguments'} or self.phase!='await_tool':raise Refused('tool unavailable')
            self.phase='tool_unknown'
            result=self.tool.call('factory-probe',value['arguments'])
            if post(self.journal+'/bind',{'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','assistant':self.assistant,'tool_result':result})!=(200,True):raise Refused('journal bind failed')
            self.tool_result=result;self.phase='bound';return result['content']
        if set(value)!={'type','body'}:raise Refused('invalid request')
        body=value['body']
        if (not isinstance(body,dict) or set(body)!={'model','messages','tools','max_tokens','stream','stream_options'} or body['model']!='gpt-4o-mini' or body['tools']!=[TOOL] or body['max_tokens']!=16384 or body['stream'] is not True or body['stream_options']!={'include_usage':True}):raise Refused('invalid inference')
        routed={**body,'model':'auto'}
        if self.phase=='initial':
            if len(body['messages'])!=2 or len(encoded(routed))>65536:raise Refused('invalid initial')
            now=int(time.time()*1000);lease={'worker_id':'fixture-worker','token':'01ARZ3NDEKTSV4RRFFQ69G5FAV','attempt':1,'issued_ms':now-1000,'expires_ms':now+299000}
            def route(name,rate):return {'model':name,'review_digest':'a'*64,'reviewed_at_ms':now-1000,'valid_until_ms':now+299000,'input_microusd_per_million':rate,'output_microusd_per_million':rate,'max_billable_input_tokens':1000000,'max_billable_output_tokens':1000000,'fixed_call_microusd':0,'max_request_bytes':65536,'output_limit_field':'max_tokens'}
            spec={'lease':lease,'initial':encoded(routed),'tool':TOOL,'max_tokens':16384,'routes':[route('fixture-cheap',100),route('fixture-expensive',200)]}
            if post(self.journal+'/initialize',spec)[0]!=200:raise Refused('initialize failed')
            admission={'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','turn':0,'request':encoded(routed)}
            self.phase='inference_unknown'
            if post(self.journal+'/prepare',admission)!=(200,True) or post(self.journal+'/begin',admission)!=(200,True):raise Refused('admission failed')
            call={'id':'factory-probe','type':'function','function':{'name':'factory__shell','arguments':json.dumps(ARGS,separators=(',',':'))}}
            self.assistant={'role':'assistant','content':None,'tool_calls':[call]};self.initial=body
            self.tool.record_provider_call('factory-probe',ARGS);self.phase='await_tool'
            result=sse({'role':'assistant','tool_calls':[{'index':0,**call}]},'tool_calls')
        elif self.phase=='bound':
            expected={**self.initial,'messages':self.initial['messages']+[self.assistant,self.tool_result]}
            if body!=expected:raise Refused('unattested continuation')
            admission={'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAX','turn':1,'request':encoded(routed)}
            self.phase='inference_unknown'
            if post(self.journal+'/prepare',admission)!=(200,True) or post(self.journal+'/begin',admission)!=(200,True):raise Refused('admission failed')
            result=sse({'role':'assistant','content':'OFFLINE_FACTORY_DONE'},'stop');self.phase='done'
        else:raise Refused('inference unavailable')
        return base64.b64encode(result).decode()
