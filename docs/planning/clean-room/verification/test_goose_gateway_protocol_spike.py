#!/usr/bin/env python3
"""Negative controls for the fixture-only Goose gateway proxy."""
import copy
import http.client
import http.server
import json
import threading
import unittest

import goose_gateway_protocol_spike as spike


def request():
    return {'model':spike.MODEL, 'messages':[{'role':'system','content':'system'},{'role':'user','content':'user'}],
            'tools':[copy.deepcopy(spike.TOOL)], 'max_tokens':16384, 'stream':True,
            'stream_options':{'include_usage':True}}


class Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        self.server.requests += 1
        body = self.server.body
        self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.upstream = http.server.ThreadingHTTPServer(('127.0.0.1',0), Upstream)
        self.upstream.requests = 0; self.upstream.body = b'not sse'
        self.proxy = http.server.ThreadingHTTPServer(('127.0.0.1',0), spike.Proxy)
        self.proxy.records=[]; self.proxy.arguments={}; self.proxy.lock=threading.Lock()
        self.proxy.reservations=0; self.proxy.spent=0; self.proxy.upstream=self.upstream
        self.proxy.upstream_url='http://127.0.0.1:%d/v1/chat/completions' % self.upstream.server_address[1]
        self.threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (self.upstream,self.proxy)]
        for t in self.threads:t.start()
    def tearDown(self):
        for s in (self.proxy,self.upstream):s.shutdown();s.server_close()
        for t in self.threads:t.join()
    def post(self, body, route='/v1/chat/completions'):
        connection=http.client.HTTPConnection('127.0.0.1',self.proxy.server_address[1],timeout=5)
        connection.request('POST',route,body,{'Content-Type':'application/json'})
        response=connection.getresponse(); status=response.status; response.read(); connection.close(); return status
    def test_malformed_oversize_unknown_fields_and_mismatched_tool_result_never_reserve_or_forward(self):
        mismatch=request()
        mismatch['messages'] += [{'role':'assistant','content':None,'tool_calls':[{'id':'call-a','type':'function','function':{'name':'factory__shell','arguments':'{"command":"true"}'}}]}, {'role':'tool','tool_call_id':'call-b','content':'{}'}]
        unknown=request();unknown['surprise']=True
        for raw,route in [(b'{','/v1/chat/completions'),(json.dumps(mismatch).encode(),'/v1/chat/completions'),(json.dumps(unknown).encode(),'/v1/chat/completions'),(json.dumps(request()).encode(),'/v1/other')]:
            self.assertEqual(self.post(raw,route),400)
        conn=http.client.HTTPConnection('127.0.0.1',self.proxy.server_address[1],timeout=5)
        conn.putrequest('POST','/v1/chat/completions');conn.putheader('Content-Length',str(spike.LIMIT+1));conn.endheaders()
        response=conn.getresponse();self.assertEqual(response.status,400);response.read();conn.close()
        self.assertEqual((self.proxy.reservations,self.upstream.requests),(0,0))
    def test_denied_budget_never_calls_provider(self):
        self.proxy.spent=spike.MAX_SPEND
        self.assertEqual(self.post(json.dumps(request()).encode()),402)
        self.assertEqual((self.proxy.reservations,self.upstream.requests),(0,0))
    def test_bad_and_oversized_upstream_output_withheld_and_reservations_retained(self):
        for data in [b'invalid', b'x'*(spike.LIMIT+1)]:
            self.upstream.body=data
            self.assertEqual(self.post(json.dumps(request()).encode()),502)
        self.assertEqual((self.proxy.reservations,self.proxy.spent,self.upstream.requests),(2,2*spike.RESERVATION,2))


if __name__ == '__main__':unittest.main()
