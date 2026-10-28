#!/usr/bin/env python3
"""Fresh synthetic two-turn journal; its callers are trusted fixture processes only."""
import json
import time
from atomic_inference_fixture import post


def exercise(base):
    now=int(time.time()*1000)
    lease={'worker_id':'fixture-worker','token':'01ARZ3NDEKTSV4RRFFQ69G5FAV','attempt':1,'issued_ms':now-1000,'expires_ms':now+299000}
    tool={'type':'function','function':{'name':'factory__shell','parameters':{'type':'object'}}}
    initial={'model':'auto','messages':[{'role':'system','content':'system'},{'role':'user','content':'task'}],'tools':[tool],'max_tokens':100,'stream':True,'stream_options':{'include_usage':True}}
    raw=lambda v:list(json.dumps(v,separators=(',',':')).encode())
    def route(name,rate):return {'model':name,'review_digest':'a'*64,'reviewed_at_ms':now-1000,'valid_until_ms':now+299000,'input_microusd_per_million':rate,'output_microusd_per_million':rate,'max_billable_input_tokens':1000000,'max_billable_output_tokens':1000000,'fixed_call_microusd':0,'max_request_bytes':65536,'output_limit_field':'max_tokens'}
    spec={'lease':lease,'initial':raw(initial),'tool':tool,'max_tokens':100,'routes':[route('fixture-cheap',100),route('fixture-expensive',200)]}
    first={'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','turn':0,'request':raw(initial)}
    assistant={'role':'assistant','content':None,'tool_calls':[{'id':'tool-1','type':'function','function':{'name':'factory__shell','arguments':'{"command":"echo hi"}'}}]}
    result={'role':'tool','tool_call_id':'tool-1','content':'masked fixture output'}
    exchange={'call_id':first['call_id'],'assistant':assistant,'tool_result':result}
    second={'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAX','turn':1,'request':raw({**initial,'messages':initial['messages']+[assistant,result]})}
    url=base+'/restate/call/ConversationFixture/conversation-one'
    assert post(url+'/initialize',spec)[0]==200
    assert post(url+'/prepare',second)[0]==409
    assert post(url+'/prepare',first)==(200,True)
    assert post(url+'/prepare',first)[0]==409
    assert post(url+'/begin',first)==(200,True)
    assert post(url+'/begin',first)[0]==409
    forged={**exchange,'tool_result':{**result,'tool_call_id':'other'}}
    assert post(url+'/bind',forged)[0]==400
    assert post(url+'/bind',exchange)==(200,True)
    forged_request={**initial,'messages':initial['messages']+[assistant,{**result,'content':'forged'}]}
    assert post(url+'/prepare',{**second,'request':raw(forged_request)})[0]==403
    assert post(url+'/prepare',second)==(200,True)
    assert post(url+'/begin',second)==(200,True)
    assert post(url+'/begin',second)[0]==409
    revoked=base+'/restate/call/ConversationFixture/conversation-revoked'
    assert post(revoked+'/initialize',spec)[0]==200
    assert post(revoked+'/prepare',first)==(200,True)
    assert post(revoked+'/revoke',lease)==(200,True)
    assert post(revoked+'/begin',first)[0]==409
    cap=base+'/restate/call/ConversationFixture/conversation-cap'
    expensive={**spec,'routes':[route('fixture-cheap',100),route('fixture-expensive',200000)]}
    assert post(cap+'/initialize',expensive)[0]==200
    assert post(cap+'/prepare',first)==(200,True)
    assert post(cap+'/begin',first)==(200,True)
    assert post(cap+'/bind',exchange)==(200,True)
    assert post(cap+'/prepare',second)[0]==429
    print('PASS: synthetic conversation binds prior tool IDs and reserves max route cost in one disposable journal',flush=True)
    return first,second,exchange,lease


def verify(base,checkpoint):
    first,second,exchange,lease=checkpoint
    url=base+'/restate/call/ConversationFixture/conversation-one'
    assert post(url+'/prepare',first)[0]==409
    assert post(url+'/begin',first)[0]==409
    assert post(url+'/prepare',second)[0]==409
    assert post(url+'/begin',second)[0]==409
    assert post(url+'/bind',exchange)[0]==409
    revoked=base+'/restate/call/ConversationFixture/conversation-revoked'
    assert post(revoked+'/begin',first)[0]==409
    cap=base+'/restate/call/ConversationFixture/conversation-cap'
    assert post(cap+'/prepare',second)[0]==429
