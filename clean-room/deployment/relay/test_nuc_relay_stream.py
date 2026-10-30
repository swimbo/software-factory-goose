import json
import unittest
from nuc_relay_authority import Denied
from nuc_relay_stream import parse

def event(delta, finish=None, model='allowed', ident='resp1'):
    return 'data: '+json.dumps({'id':ident,'model':model,'object':'chat.completion.chunk','choices':[{'index':0,'delta':delta,'finish_reason':finish}]})+'\n\n'
def wire(*parts):
    return (''.join(parts)+'data: [DONE]\n\n').encode()
def call(arguments):
    return {'index':0,'id':'tool1','type':'function','function':{'name':'factory__write_files','arguments':arguments}}

class StreamBoundary(unittest.TestCase):
    def test_stream_accepts_fragmented_fixed_write_files(self):
        first={'index':0,'id':'tool1','type':'function','function':{'name':'factory__write_files','arguments':'{"files":{"hello.py":"x",'}}
        second={'index':0,'function':{'arguments':'"test_hello.py":"y"}}'}}
        result=parse(wire(event({'tool_calls':[first]}),event({'tool_calls':[second]}),event({},'tool_calls')),{'allowed'})
        self.assertEqual(result['arguments'], {'files':{'hello.py':'x','test_hello.py':'y'}})
    def test_unreviewed_models_changed_identity_and_truncation_fail_closed(self):
        for raw in [wire(event({'content':'x'},model='fallback'),event({},'stop',model='fallback')),
                    wire(event({'role':'assistant'}),event({},'stop',ident='other')),
                    wire(event({},'stop'))[:-4]]:
            with self.assertRaises(Denied):parse(raw,{'allowed'})
    def test_fixed_payload_and_duplicate_keys_are_required(self):
        for arg in ['{"files":{"hello.py":"x","test_hello.py":"y"},"command":"id"}',
                    '{"files":{"hello.py":"x","hello.py":"y","test_hello.py":"z"}}',
                    '{"files":{"../hello.py":"x","test_hello.py":"y"}}']:
            with self.assertRaises(Denied):parse(wire(event({'tool_calls':[call(arg)]}),event({},'tool_calls')),{'allowed'})
    def test_unknown_stream_fields_and_multiple_calls_fail(self):
        valid='{"files":{"hello.py":"x","test_hello.py":"y"}}'
        for delta in [{'audio':'unexpected'}, {'tool_calls':[call(valid),call(valid)]}]:
            with self.assertRaises(Denied):parse(wire(event(delta),event({},'stop')),{'allowed'})
    def test_boolean_indices_and_unsafe_tool_identity_fail(self):
        valid='{"files":{"hello.py":"x","test_hello.py":"y"}}'
        for item in [{**call(valid),'index':False}, {**call(valid),'id':'../tool'}]:
            with self.assertRaises(Denied):parse(wire(event({'tool_calls':[item]}),event({},'tool_calls')),{'allowed'})

if __name__=='__main__':unittest.main()
