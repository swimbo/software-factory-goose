#!/usr/bin/env python3
"""Peer-authenticated synthetic launcher wired to one same-object admission authority."""
import concurrent.futures
import hashlib
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import urllib.error
import urllib.request

from inference_gate_fixture import unique_object
from peer_catalog_gate_fixture import UnixServer, assert_wrong_peer_denied, invoke, peer_uid, post
from trusted_inference_launcher_fixture import Provider

RACE='01ARZ3NDEKTSV4RRFFQ69G5FCG'
BEFORE='01ARZ3NDEKTSV4RRFFQ69G5FCH'
AFTER='01ARZ3NDEKTSV4RRFFQ69G5FCJ'
DROP='01ARZ3NDEKTSV4RRFFQ69G5FCK'
PAYLOAD=b'{"purpose":"synthetic"}'


class AtomicGate(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def reply(self,status,body):
        data=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_POST(self):
        try:
            uid=peer_uid(self.connection)
            if uid!=self.server.expected_uid:
                self.server.denied_uid=uid
                self.server.peer_denied.set()
                try:self.reply(403,{'error':'peer denied'})
                except (BrokenPipeError, ConnectionResetError):pass
                return
            if self.path!='/infer':raise ValueError('route')
            length=int(self.headers.get('Content-Length','-1'))
            if not 0<length<=4096:raise ValueError('size')
            body=json.loads(self.rfile.read(length),object_pairs_hook=unique_object)
            if not isinstance(body,dict) or set(body)!={'task','call_id','payload'}:raise ValueError('shape')
            entry=self.server.catalog.get(body['call_id'])
            if not entry or body['task']!=entry['task'] or body['payload']!={'purpose':'synthetic'}:raise ValueError('catalog mismatch')
            # Fixed catalog, not caller input, supplies task, lease, reviewed model, cost,
            # digest and provider request bytes. This is synthetic trusted bootstrap.
            endpoint=self.server.restate+'/restate/call/AtomicInferenceFixture/'+entry['task']
            code,stage=post(endpoint+'/prepare',entry['call'])
            if code!=200 or stage!='Reserved':self.reply(409,{'error':'not reserved'});return
            if body['call_id']==BEFORE:
                self.server.before.set()
                if not self.server.resume_before.wait(10):raise ValueError('fixture barrier timeout')
            code,_=post(endpoint+'/begin',entry['call'])
            if code!=200:self.reply(409,{'error':'not admitted'});return
            if body['call_id']==AFTER:
                self.server.after.set()
                if not self.server.resume_after.wait(10):raise ValueError('fixture barrier timeout')
            request=urllib.request.Request(self.server.provider+'/fixture',data=PAYLOAD,method='POST',headers={'Content-Type':'application/json','X-Fixture-Call':body['call_id']})
            try:
                with urllib.request.urlopen(request,timeout=5) as response:
                    response.read();outcome='sent' if response.status==200 else 'unknown'
            except (OSError,urllib.error.URLError):outcome='unknown'
            self.reply(200,{'outcome':outcome})
        except (ValueError,TypeError,KeyError,OSError):self.reply(400,{'error':'invalid request'})


def exercise(base, env, temp):
    now=int(time.time()*1000)
    lease={'worker_id':'fixture-worker','token':'01ARZ3NDEKTSV4RRFFQ69G5FAV','attempt':1,'issued_ms':now-1000,'expires_ms':now+299000}
    entries={}
    for call_id,task in [(RACE,'atomic-peer-race'),(BEFORE,'atomic-peer-before'),(AFTER,'atomic-peer-after'),(DROP,'atomic-peer-drop')]:
        call={'call_id':call_id,'request_digest':hashlib.sha256(PAYLOAD).hexdigest(),'review_digest':'b'*64,'model':'fixture-model','amount_microusd':1000,'worker_id':lease['worker_id'],'token':lease['token'],'attempt':lease['attempt']}
        entries[call_id]={'task':task,'lease':lease,'call':call}
        assert post(base+'/restate/call/AtomicInferenceFixture/'+task+'/initialize',lease)[0]==200
    upstream=http.server.ThreadingHTTPServer(('127.0.0.1',0),Provider)
    upstream.guard=threading.Lock();upstream.calls={};upstream.drop_id=DROP;upstream.hang_id='unused'
    upstream.accepted=threading.Event();upstream.release=threading.Event()
    provider='http://127.0.0.1:%d'%upstream.server_address[1]
    owned=tempfile.TemporaryDirectory(prefix='.ap-',dir=Path(__file__).resolve().parents[2]);os.chmod(owned.name,0o700)
    path=str(Path(owned.name)/'a');wrong_path=str(Path(owned.name)/'b')
    servers=[];threads=[]
    try:
        for socket_path,uid in [(path,os.geteuid()),(wrong_path,os.geteuid()+1)]:
            server=UnixServer(socket_path,AtomicGate);os.chmod(socket_path,0o600)
            server.expected_uid=uid;server.restate=base;server.provider=provider;server.catalog=entries
            server.peer_denied=threading.Event();server.denied_uid=None
            server.before=threading.Event();server.resume_before=threading.Event();server.after=threading.Event();server.resume_after=threading.Event()
            servers.append(server)
        for server in [upstream,*servers]:
            t=threading.Thread(target=server.serve_forever,daemon=True);t.start();threads.append((server,t))
        def body(call_id):return {'task':entries[call_id]['task'],'call_id':call_id,'payload':{'purpose':'synthetic'}}
        assert_wrong_peer_denied(wrong_path,body(RACE),servers[1])
        for bad in [{**body(RACE),'task':entries[DROP]['task']},{**body(RACE),'uid':os.geteuid()},{**body(RACE),'call_id':'forged'},{**body(RACE),'payload':{'purpose':'synthetic','changed':True}},{**body(RACE),'begin':True}]:
            assert invoke(path,bad)[0]==400
        for field in ('token','attempt','amount_microusd','request_digest','review_digest','provider'):
            assert invoke(path,{**body(RACE),field:'forged'})[0]==400
        assert not upstream.calls
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results=list(pool.map(lambda _:invoke(path,body(RACE),{'X-Worker-Uid':'forged'}),range(10)))
        assert sum(1 for code,value in results if code==200 and value.get('outcome')=='sent')==1,results
        assert upstream.calls=={RACE:1},upstream.calls
        # A synthetic provider accepting and dropping the response is not retried.
        assert invoke(path,body(DROP))==(200,{'outcome':'unknown'})
        assert invoke(path,body(DROP))[0]==409 and upstream.calls[DROP]==1
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending=pool.submit(invoke,path,body(BEFORE));assert servers[0].before.wait(10)
            endpoint=base+'/restate/call/AtomicInferenceFixture/'+entries[BEFORE]['task']
            assert post(endpoint+'/revoke',lease)[0]==200
            servers[0].resume_before.set();assert pending.result(timeout=10)[0]==409
        assert BEFORE not in upstream.calls
        # Explicit ordering limitation: revoke after successful begin does not cancel
        # the already authorized action, which can still reach the synthetic provider.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending=pool.submit(invoke,path,body(AFTER));assert servers[0].after.wait(10)
            endpoint=base+'/restate/call/AtomicInferenceFixture/'+entries[AFTER]['task']
            assert post(endpoint+'/revoke',lease)[0]==200
            servers[0].resume_after.set();assert pending.result(timeout=10)==(200,{'outcome':'sent'})
        assert upstream.calls=={RACE:1,DROP:1,AFTER:1},upstream.calls
        print('PASS: peer-gated same-authority fixture rejects forgery/duplicates and enforces revocation-before-begin; begin-first can still send',flush=True)
        return entries
    finally:
        upstream.release.set()
        for s in servers:s.resume_before.set();s.resume_after.set()
        for s,t in reversed(threads):s.shutdown();s.server_close();t.join(timeout=5)
        for s in servers:
            if s not in [server for server,_ in threads]:s.server_close()
        for socket_path in (path,wrong_path):
            try:os.unlink(socket_path)
            except FileNotFoundError:pass
        owned.cleanup()


def verify(base, entries):
    for call_id,entry in entries.items():
        endpoint=base+'/restate/call/AtomicInferenceFixture/'+entry['task']
        expected='Reserved' if call_id==BEFORE else 'DispatchingUnknown'
        assert post(endpoint+'/inspect',entry['call'])==(200,expected)
        assert post(endpoint+'/begin',entry['call'])[0]==409
