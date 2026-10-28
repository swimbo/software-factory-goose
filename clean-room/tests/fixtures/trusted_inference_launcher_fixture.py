#!/usr/bin/env python3
"""Disposable trusted launcher experiment. Synthetic provider; never production authority."""
import concurrent.futures
import hashlib
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


def post(url, body, headers=None):
    request=urllib.request.Request(url, data=body, method='POST', headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            data=response.read()
            return response.status, json.loads(data) if data else None
    except urllib.error.HTTPError as error:
        return error.code, None


def binding(call_id, payload):
    return {'call_id':call_id,'request_digest':hashlib.sha256(payload).hexdigest(),
            'review_digest':'b'*64,'model':'fixture-model','attempt':1,'amount_microusd':1000}


def launch(base, provider, call_id, payload, stop_after_begin=False):
    """Fixture caller has fixed URLs and trusted local ID; never retry an ambiguous begin/call."""
    request=binding(call_id,payload)
    encoded=json.dumps(request,sort_keys=True,separators=(',',':')).encode()
    headers={'Content-Type':'application/json'}
    authority=base+'/restate/call/InferenceAuthority/launcher-unit'
    try:
        code,stage=post(authority+'/prepare',encoded,headers)
        if code!=200 or stage!='Reserved': return 'refused'
        code,_=post(authority+'/begin',encoded,headers)
        if code!=200:return 'refused'
        if stop_after_begin: os._exit(71)
        code,_=post(provider+'/fixture',payload,{'Content-Type':'application/json','X-Fixture-Call':call_id})
        return 'sent' if code==200 else 'unknown'
    except (OSError, urllib.error.URLError):
        return 'unknown'


class Provider(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def do_POST(self):
        assert self.path=='/fixture'
        length=int(self.headers['Content-Length'])
        assert 0<length<=1024
        payload=self.rfile.read(length)
        assert json.loads(payload)['purpose']=='synthetic'
        call_id=self.headers['X-Fixture-Call']
        with self.server.guard:
            self.server.calls[call_id]=self.server.calls.get(call_id,0)+1
        if call_id==self.server.drop_id:
            self.close_connection=True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        if call_id==self.server.hang_id:
            self.server.accepted.set()
            self.server.release.wait(timeout=10)
        try:
            data=b'{}'
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError): pass


def child(base, provider, call_id, mode):
    payload=b'{"purpose":"synthetic"}'
    return launch(base,provider,call_id,payload,stop_after_begin=mode=='crash-before-send')


def exercise(base, env):
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Provider)
    server.guard=threading.Lock();server.calls={}
    server.drop_id='01ARZ3NDEKTSV4RRFFQ69G5FB2'
    server.hang_id='01ARZ3NDEKTSV4RRFFQ69G5FB4'
    server.accepted=threading.Event();server.release=threading.Event()
    provider='http://127.0.0.1:%d'%server.server_address[1]
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    payload=b'{"purpose":"synthetic"}'
    race_id='01ARZ3NDEKTSV4RRFFQ69G5FB1'
    pre_id='01ARZ3NDEKTSV4RRFFQ69G5FB3'
    lost_begin_id='01ARZ3NDEKTSV4RRFFQ69G5FB5'
    lost_prepare_id='01ARZ3NDEKTSV4RRFFQ69G5FB6'
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            outcomes=list(pool.map(lambda _:launch(base,provider,race_id,payload),range(10)))
        assert outcomes.count('sent')==1,outcomes
        assert server.calls.get(race_id)==1,server.calls
        assert launch(base,provider,race_id,b'{"purpose":"synthetic","changed":true}')=='refused'
        assert server.calls.get(race_id)==1
        assert launch(base,provider,server.drop_id,payload)=='unknown'
        assert server.calls.get(server.drop_id)==1
        assert launch(base,provider,server.drop_id,payload)=='refused'
        assert server.calls.get(server.drop_id)==1
        parsed=urllib.parse.urlsplit(base)
        encoded=json.dumps(binding(lost_prepare_id,payload),sort_keys=True,separators=(',',':')).encode()
        with socket.create_connection((parsed.hostname,parsed.port),timeout=5) as wire:
            wire.sendall(b'POST /restate/call/InferenceAuthority/launcher-unit/prepare HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(encoded)).encode()+b'\r\n\r\n'+encoded)
            assert wire.recv(1)==b'H'
        assert launch(base,provider,lost_prepare_id,payload)=='sent'
        assert launch(base,provider,lost_prepare_id,payload)=='refused' and server.calls.get(lost_prepare_id)==1
        encoded=json.dumps(binding(lost_begin_id,payload),sort_keys=True,separators=(',',':')).encode()
        authority=base+'/restate/call/InferenceAuthority/launcher-unit'
        assert post(authority+'/prepare',encoded,{'Content-Type':'application/json'})==(200,'Reserved')
        with socket.create_connection((parsed.hostname,parsed.port),timeout=5) as wire:
            wire.sendall(b'POST /restate/call/InferenceAuthority/launcher-unit/begin HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(encoded)).encode()+b'\r\n\r\n'+encoded)
            assert wire.recv(1)==b'H'
        assert launch(base,provider,lost_begin_id,payload)=='refused' and server.calls.get(lost_begin_id,0)==0
        executable=[sys.executable,os.path.abspath(__file__),'--child',base,provider]
        before=subprocess.run(executable+[pre_id,'crash-before-send'],env=env,timeout=10)
        assert before.returncode==71,before.returncode
        assert launch(base,provider,pre_id,payload)=='refused' and server.calls.get(pre_id,0)==0
        after=subprocess.Popen(executable+[server.hang_id,'normal'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            assert server.accepted.wait(10),'provider did not accept child call'
            after.kill();after.wait(timeout=5)
            assert launch(base,provider,server.hang_id,payload)=='refused'
            assert server.calls.get(server.hang_id)==1
        finally:
            if after.poll() is None:after.kill();after.wait(timeout=5)
            server.release.set()
        print('PASS: fixture launcher sends at most once across concurrent, lost-ack and process-death controls', flush=True)
        return {'race_id':race_id,'dropped_provider_id':server.drop_id,'lost_prepare_id':lost_prepare_id,'lost_begin_id':lost_begin_id,'crash_before_id':pre_id,'crash_after_id':server.hang_id}
    finally:
        server.release.set();server.shutdown();server.server_close();thread.join(timeout=5)


def verify_after_restart(base, ids):
    authority=base+'/restate/call/InferenceAuthority/launcher-unit'
    for call_id in ids.values():
        encoded=json.dumps(binding(call_id,b'{"purpose":"synthetic"}'),sort_keys=True,separators=(',',':')).encode()
        assert post(authority+'/prepare',encoded,{'Content-Type':'application/json'})==(200,'DispatchingUnknown')
        assert post(authority+'/begin',encoded,{'Content-Type':'application/json'})[0]==409


if __name__=='__main__':
    if len(sys.argv)!=6 or sys.argv[1]!='--child': raise SystemExit('fixture child only')
    raise SystemExit(0 if child(*sys.argv[2:])=='sent' else 1)
