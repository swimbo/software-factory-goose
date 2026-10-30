import hashlib
import datetime
import json
import unittest
from unittest.mock import patch
from nuc_relay_authority import Denied, WRITE_TOOL
from nuc_relay_core import RelayCore, _encode
from test_nuc_relay_stream import event, wire, call
G='01ARZ3NDEKTSV4RRFFQ69G5FAV'
def initial():
    return {'model':'gpt-4o-mini','messages':[{'role':'system','content':'fixed'}, {'role':'user','content':'task\n<turn-context>\n<current-time>'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S +00:00')+'</current-time>\n<working-directory>/work/task</working-directory>\n</turn-context>'}], 'tools':[WRITE_TOOL], 'max_tokens':16384,'stream':True,'stream_options':{'include_usage':True}}
def scope():
    value=initial();value['messages'][1]['content']='task'
    digest=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    return {'schema':2,'request_contract':'goose-turn-context-v1','generation':G,'request_sha256':digest, 'allowed_models':['allowed']}
class Fence:
    def __init__(self):self.seen=set()
    def begin(self,g,kind,digest):
        if (g,kind) in self.seen:raise Denied('already fenced')
        self.seen.add((g,kind))

class RelayLoop(unittest.TestCase):
    def build(self, transport, writer):
        with patch('nuc_relay_core.load_root_scope',return_value=(scope(),{})):
            return RelayCore(0,0,0,0,Fence(),lambda _:True,transport,writer)
    def test_synthetic_full_loop_and_fixed_route(self):
        args={'files':{'hello.py':'x','test_hello.py':'y'}}
        stream=wire(event({'tool_calls':[call(json.dumps(args,separators=(',',':')))]}),event({},'tool_calls'))
        final=wire(event({'content':'done'}),event({},'stop'))
        sent=[]
        def transport(body):
            sent.append(body);return [stream,final][len(sent)-1]
        writes=[]
        def writer(body):
            writes.append(body);return {'status':'executed','exit_code':0,'stdout':'Both task files written.','stderr':''}
        relay=self.build(transport,writer)
        with patch('nuc_relay_core.require_worker_peer'):
            relay.call(None,{'type':'inference','body':initial()})
            relay.call(None,{'type':'tool','arguments':args})
            continuation=dict(initial());continuation['messages']=initial()['messages']+[relay.assistant,relay.tool_response]
            relay.call(None,{'type':'inference','body':continuation})
            with self.assertRaises(Denied):relay.call(None,{'type':'inference','body':continuation})
        self.assertEqual([v['model'] for v in sent],['auto','auto'])
        self.assertEqual(writes,[args])
        self.assertEqual({x[1] for x in relay.fence.seen},{'inference0','writer','inference1'})
    def test_unknown_provider_effect_is_never_retried(self):
        calls=[]
        def fail(body):calls.append(body);raise OSError('lost')
        relay=self.build(fail,lambda _:None)
        with patch('nuc_relay_core.require_worker_peer'):
            for _ in range(2):
                with self.assertRaises(Denied):relay.call(None,{'type':'inference','body':initial()})
        self.assertEqual(len(calls),1)
    def test_stop_during_inference_keeps_effect_unknown_and_hides_result(self):
        checks=[]; calls=[]
        relay=self.build(lambda body: calls.append(body) or wire(event({},'stop')),lambda _:None)
        def guard(_):
            checks.append(1)
            return len(checks) == 1
        relay.guard=guard
        with patch('nuc_relay_core.require_worker_peer'):
            for _ in range(2):
                with self.assertRaises(Denied):relay.call(None,{'type':'inference','body':initial()})
        self.assertEqual(len(calls),1)
        self.assertEqual(relay.phase,'unknown')

if __name__=='__main__':unittest.main()
