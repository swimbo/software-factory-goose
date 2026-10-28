import threading
import unittest
from trusted_tool_relay import ToolRelay, Refused

class RelayTests(unittest.TestCase):
    def test_only_recorded_exact_call_executes_and_replay_is_fenced(self):
        calls=[]
        relay=ToolRelay(lambda args: calls.append(args) or {'status':'executed','exit_code':0,'stdout':'safe','stderr':''})
        relay.record_provider_call('provider-1',{'command':'true'})
        for ident,args in [('bad',{'command':'true'}),('provider-1',{'command':'other'}),('provider-1',{'command':'true','result':'forged'})]:
            with self.assertRaises(Refused): relay.call(ident,args)
        self.assertEqual(calls,[])
        self.assertEqual(relay.call('provider-1',{'command':'true'})['content'], '{"status":"executed","exit_code":0,"stdout":"safe","stderr":""}')
        with self.assertRaises(Refused): relay.call('provider-1',{'command':'true'})
        with self.assertRaises(Refused): relay.record_provider_call('provider-1',{'command':'true'})
        self.assertEqual(len(calls),1)

    def test_unknown_result_and_racing_call_cannot_retry(self):
        entered=threading.Event();release=threading.Event();calls=[]
        def execute(args):
            calls.append(args);entered.set();release.wait(2);raise RuntimeError('unknown')
        relay=ToolRelay(execute);relay.record_provider_call('id',{'command':'true'})
        def first():
            try: relay.call('id',{'command':'true'})
            except Refused: pass
        thread=threading.Thread(target=first);thread.start();self.assertTrue(entered.wait(2))
        with self.assertRaises(Refused):relay.call('id',{'command':'true'})
        release.set();thread.join(2);self.assertFalse(thread.is_alive());self.assertEqual(len(calls),1)
        with self.assertRaises(Refused):relay.call('id',{'command':'true'})

    def test_untrusted_or_oversized_executor_result_is_rejected(self):
        for value in ({'status':'executed','exit_code':0,'stdout':'x'*65536,'stderr':''}, {'status':'executed','exit_code':True,'stdout':'','stderr':''}, {'status':'refused','reason':'secret'}):
            relay=ToolRelay(lambda _args:value);relay.record_provider_call('id',{'command':'true'})
            with self.assertRaises(Refused):relay.call('id',{'command':'true'})
            with self.assertRaises(Refused):relay.call('id',{'command':'true'})

if __name__=='__main__':unittest.main()
