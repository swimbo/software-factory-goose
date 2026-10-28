#!/usr/bin/env python3
"""Local authorization/egress canary, synthetic only; NOT production ingress."""
import http.server
import json
from pathlib import Path
import socket
import subprocess
import threading
import urllib.parse

from trusted_inference_launcher_fixture import Provider, launch

RACE='01ARZ3NDEKTSV4RRFFQ69G5FB7'
DROP='01ARZ3NDEKTSV4RRFFQ69G5FB8'
UNUSED='01ARZ3NDEKTSV4RRFFQ69G5FB9'
PAYLOAD=b'{"purpose":"synthetic"}'


def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate key')
        result[key]=value
    return result


class Gate(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_POST(self):
        try:
            if self.path!='/infer':raise ValueError('unknown route')
            n=int(self.headers.get('Content-Length','-1'))
            if not 0<n<=4096:raise ValueError('size')
            request=json.loads(self.rfile.read(n),object_pairs_hook=unique_object)
            if not isinstance(request,dict) or set(request)!={'call_id','payload'}:raise ValueError('shape')
            if request['call_id'] not in (RACE,DROP,UNUSED) or request['payload']!={'purpose':'synthetic'}:raise ValueError('catalog')
            # The catalog supplies the only bytes passed to the authority/provider. No caller
            # may supply a URL, receipt, digest, amount, credential, begin result or tool.
            outcome=launch(self.server.restate,self.server.provider,request['call_id'],PAYLOAD)
            body=json.dumps({'outcome':outcome}).encode()
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        except (ValueError,TypeError,KeyError):
            self.send_error(400)


WORKER=r'''
import concurrent.futures,errno,json,socket,sys,urllib.error,urllib.request
port,provider,restate=map(int,sys.argv[1:])
url='http://127.0.0.1:%d'%port
race='01ARZ3NDEKTSV4RRFFQ69G5FB7';drop='01ARZ3NDEKTSV4RRFFQ69G5FB8';unused='01ARZ3NDEKTSV4RRFFQ69G5FB9'
for target in (provider,restate):
 s=socket.socket();s.settimeout(1);code=s.connect_ex(('127.0.0.1',target));s.close();assert code==errno.EPERM,(target,code)
def call(path,body):
 req=urllib.request.Request(url+path,data=body,method='POST',headers={'Content-Type':'application/json'})
 try:
  with urllib.request.urlopen(req,timeout=10) as r:return r.status,json.loads(r.read())
 except urllib.error.HTTPError as e:return e.code,None
def body(i):return json.dumps({'call_id':i,'payload':{'purpose':'synthetic'}}).encode()
for route,data in [('/begin',body(unused)),('/infer',b'{"call_id":"01ARZ3NDEKTSV4RRFFQ69G5FB9","call_id":"01ARZ3NDEKTSV4RRFFQ69G5FB9","payload":{"purpose":"synthetic"}}'),('/infer',json.dumps({'call_id':unused,'payload':{'purpose':'synthetic'},'begin':True}).encode()),('/infer',json.dumps({'call_id':unused,'payload':{'purpose':'synthetic','changed':True}}).encode()),('/infer',json.dumps({'call_id':'forged','payload':{'purpose':'synthetic'}}).encode())]:
 assert call(route,data)[0]==400
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
 results=list(pool.map(lambda _:call('/infer',body(race)),range(10)))
assert sum(1 for status,r in results if status==200 and r.get('outcome')=='sent')==1,results
assert all(status==200 and set(r)=={'outcome'} for status,r in results),results
assert call('/infer',body(drop))==(200,{'outcome':'unknown'})
assert call('/infer',body(drop))==(200,{'outcome':'refused'})
assert call('/infer',body(unused))==(200,{'outcome':'sent'})
print(json.dumps({'direct_provider_denied':True,'direct_authority_denied':True,'racing_one_send':True,'forged_rejected':True,'uncertain_no_resend':True,'unused_sent_once':True}))
'''


def exercise(base, env, temp):
    upstream=http.server.ThreadingHTTPServer(('127.0.0.1',0),Provider)
    upstream.guard=threading.Lock();upstream.calls={};upstream.drop_id=DROP;upstream.hang_id='unused'
    upstream.accepted=threading.Event();upstream.release=threading.Event()
    provider='http://127.0.0.1:%d'%upstream.server_address[1]
    gate=http.server.ThreadingHTTPServer(('127.0.0.1',0),Gate)
    gate.restate=base;gate.provider=provider
    threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (upstream,gate)]
    for thread in threads:thread.start()
    try:
        profile=Path(temp)/'inference-gate-fixture.sb'
        profile.write_text('(version 1)\n(allow default)\n(deny network*)\n(allow network-outbound (remote tcp "localhost:%d"))\n'%gate.server_address[1])
        restate_port=urllib.parse.urlsplit(base).port
        # Positive control: both fixture listeners are reachable outside the worker sandbox.
        for port in (upstream.server_address[1],restate_port):
            with socket.socket() as probe:
                probe.settimeout(1)
                assert probe.connect_ex(('127.0.0.1',port))==0
        args=['/usr/bin/sandbox-exec','-f',str(profile),'/usr/bin/python3','-c',WORKER,str(gate.server_address[1]),str(upstream.server_address[1]),str(restate_port)]
        result=subprocess.run(args,cwd=temp,env=env,capture_output=True,text=True,timeout=45)
        if result.returncode!=0:raise RuntimeError('sandbox worker failed: '+result.stderr[-2000:])
        output=json.loads(result.stdout)
        assert all(output.values()),output
        assert upstream.calls=={RACE:1,DROP:1,UNUSED:1},upstream.calls
        print('PASS: sandbox fixture denies direct provider/Restate access; catalog-bound gate sends once despite forgery and concurrent retries',flush=True)
        return output
    finally:
        upstream.release.set()
        for s in (gate,upstream):s.shutdown();s.server_close()
        for thread in threads:thread.join(timeout=5)
