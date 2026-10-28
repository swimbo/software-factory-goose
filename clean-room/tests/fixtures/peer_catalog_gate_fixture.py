#!/usr/bin/env python3
"""Disposable Unix-peer/catalog test; not a production identity or atomic lease gate."""
import concurrent.futures
import ctypes
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import threading
import time
import tempfile
import urllib.error
import urllib.request

from trusted_inference_launcher_fixture import Provider, launch
from inference_gate_fixture import unique_object

CALL='01ARZ3NDEKTSV4RRFFQ69G5FCA'
STALE='01ARZ3NDEKTSV4RRFFQ69G5FCB'
PULL='01ARZ3NDEKTSV4RRFFQ69G5FCC'
REVOKED='01ARZ3NDEKTSV4RRFFQ69G5FCD'
LATE='01ARZ3NDEKTSV4RRFFQ69G5FCE'
PULL_LATE='01ARZ3NDEKTSV4RRFFQ69G5FCF'
PAYLOAD=b'{"purpose":"synthetic"}'


def post(url, body):
    data=None if body is None else json.dumps(body).encode()
    req=urllib.request.Request(url,data=data,method='POST',headers={} if data is None else {'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=5) as response:
            payload=response.read()
            return response.status,json.loads(payload) if payload else None
    except urllib.error.HTTPError as error:return error.code,None


def peer_uid(sock):
    libc=ctypes.CDLL(None,use_errno=True)
    get=libc.getpeereid
    get.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)]
    get.restype=ctypes.c_int
    uid=ctypes.c_uint();gid=ctypes.c_uint()
    if get(sock.fileno(),ctypes.byref(uid),ctypes.byref(gid))!=0:raise OSError(ctypes.get_errno(),'peer identity unavailable')
    return uid.value


class Gate(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def reply(self,status,body):
        data=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_POST(self):
        try:
            if peer_uid(self.connection)!=self.server.expected_uid:
                self.reply(403,{'error':'peer denied'});return
            if self.path!='/infer':raise ValueError('route')
            length=int(self.headers.get('Content-Length','-1'))
            if not 0<length<=4096:raise ValueError('size')
            body=json.loads(self.rfile.read(length),object_pairs_hook=unique_object)
            if not isinstance(body,dict) or set(body)!={'call_id','payload'}:raise ValueError('shape')
            call_id=body['call_id']
            if call_id not in self.server.catalog or body['payload']!={'purpose':'synthetic'}:raise ValueError('catalog')
            # These are server-owned fixed claim bindings, never supplied by the caller.
            task, spec, lease=self.server.catalog[call_id]
            def live():
                code,state=post(self.server.restate+'/restate/call/ClaimLeaseJournal/'+task+'/status',None)
                now=int(time.time()*1000)
                return code==200 and state and state.get('work_package_id')==task and state.get('spec')==spec and state.get('stage')=='Leased' and state.get('attempts')==lease['attempt'] and state.get('active')==lease and lease['worker_id']=='fixture-worker' and lease['issued_at_ms']<=now<lease['expires_at_ms']<=lease['hard_deadline_ms']
            if not live():
                self.reply(409,{'error':'claim not live'});return
            if call_id==REVOKED:
                self.server.checked.set()
                if not self.server.resume.wait(10):raise ValueError('fixture barrier timeout')
            # A second observation catches the tested revocation, but is not atomic with
            # begin or provider dispatch and cannot constitute production authorization.
            if not live():
                self.reply(409,{'error':'claim not live'});return
            if call_id==LATE:
                self.server.late_checked.set()
                if not self.server.late_resume.wait(10):raise ValueError('late barrier timeout')
            outcome=launch(self.server.restate,self.server.provider,call_id,PAYLOAD)
            self.reply(200,{'outcome':outcome})
        except (ValueError,TypeError,KeyError,OSError):self.reply(400,{'error':'invalid request'})


class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads=True
    request_queue_size=32


class UnixClient(http.client.HTTPConnection):
    def __init__(self,path):super().__init__('localhost',timeout=10);self.path=path
    def connect(self):self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(10);self.sock.connect(self.path)


def invoke(path,body,headers=None):
    conn=UnixClient(path)
    try:
        conn.request('POST','/infer',json.dumps(body).encode(),{'Content-Type':'application/json',**(headers or {})})
        response=conn.getresponse();return response.status,json.loads(response.read())
    finally:conn.close()


def exercise(base, env, temp):
    queue=base+'/restate/call/WorkerQueueJournal/peer-catalog-queue'
    task='peer-catalog-task';spec={'repository':'fixture','base_revision':'a'*40}
    assert post(queue+'/schedule',{'work_package_id':task,'spec':spec})[0]==200
    code,assigned=post(queue+'/pull',{'request_id':PULL,'ttl_ms':300000})
    assert code==200 and assigned['Assigned']['work_package_id']==task
    lease=assigned['Assigned']['lease'];assert lease['attempt']==1 and lease['worker_id']=='fixture-worker'
    late_queue=base+'/restate/call/WorkerQueueJournal/peer-catalog-late-queue'
    late_task='peer-catalog-late-task'
    assert post(late_queue+'/schedule',{'work_package_id':late_task,'spec':spec})[0]==200
    code,late_assigned=post(late_queue+'/pull',{'request_id':PULL_LATE,'ttl_ms':300000})
    assert code==200 and late_assigned['Assigned']['work_package_id']==late_task
    late_lease=late_assigned['Assigned']['lease'];assert late_lease['attempt']==1
    upstream=http.server.ThreadingHTTPServer(('127.0.0.1',0),Provider)
    upstream.guard=threading.Lock();upstream.calls={};upstream.drop_id='unused';upstream.hang_id='unused'
    upstream.accepted=threading.Event();upstream.release=threading.Event()
    provider='http://127.0.0.1:%d'%upstream.server_address[1]
    # macOS Unix sockets have a short pathname limit; use a new fixture-owned directory
    # under the workspace instead of the long system temporary root.
    owned=tempfile.TemporaryDirectory(prefix='.pc-',dir=Path(__file__).resolve().parents[2])
    os.chmod(owned.name,0o700)
    path=str(Path(owned.name)/'a');wrong_path=str(Path(owned.name)/'b')
    servers=[];threads=[]
    try:
        for socket_path,uid in [(path,os.geteuid()),(wrong_path,os.geteuid()+1)]:
            server=UnixServer(socket_path,Gate);os.chmod(socket_path,0o600)
            server.expected_uid=uid;server.restate=base;server.provider=provider
            server.catalog={call:(task,spec,lease) for call in (CALL,STALE,REVOKED)}
            server.catalog[LATE]=(late_task,spec,late_lease)
            server.checked=threading.Event();server.resume=threading.Event()
            server.late_checked=threading.Event();server.late_resume=threading.Event()
            servers.append(server)
        for server in [upstream,*servers]:
            t=threading.Thread(target=server.serve_forever,daemon=True);t.start();threads.append((server,t))
        payload={'call_id':CALL,'payload':{'purpose':'synthetic'}}
        assert invoke(wrong_path,payload,{'X-Worker-Uid':str(os.geteuid()+1)})[0]==403
        assert not upstream.calls
        for malformed in [{**payload,'task':task},{**payload,'uid':os.geteuid()},{**payload,'call_id':'forged'},{**payload,'payload':{'purpose':'synthetic','changed':True}}]:
            assert invoke(path,malformed)[0]==400
        assert not upstream.calls
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results=list(pool.map(lambda _:invoke(path,payload,{'X-Worker-Uid':'spoofed'}),range(10)))
        assert sum(1 for code,value in results if code==200 and value.get('outcome')=='sent')==1,results
        assert upstream.calls=={CALL:1},upstream.calls
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            paused=pool.submit(invoke,path,{'call_id':REVOKED,'payload':{'purpose':'synthetic'}})
            assert servers[0].checked.wait(10),'claim check barrier not reached'
            complete={'request_id':PULL,'proof':{'attempt':lease['attempt'],'token':lease['token']},'receipt':{'status':'failed','exit_code':1,'stderr_tail':'synthetic'}}
            code,state=post(queue+'/complete',complete);assert code==200 and state['stage']=='CoolingDown'
            servers[0].resume.set()
            assert paused.result(timeout=10)[0]==409
        assert invoke(path,{'call_id':STALE,'payload':{'purpose':'synthetic'}})[0]==409
        assert upstream.calls=={CALL:1}
        # Negative canary: a second status read cannot make a cross-object dispatch atomic.
        # Revoke only after both reads, before begin; the current fixture still sends.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            late=pool.submit(invoke,path,{'call_id':LATE,'payload':{'purpose':'synthetic'}})
            assert servers[0].late_checked.wait(10),'late claim barrier not reached'
            completion={'request_id':PULL_LATE,'proof':{'attempt':late_lease['attempt'],'token':late_lease['token']},'receipt':{'status':'failed','exit_code':1,'stderr_tail':'synthetic'}}
            code,state=post(late_queue+'/complete',completion);assert code==200 and state['stage']=='CoolingDown'
            servers[0].late_resume.set()
            assert late.result(timeout=10)==(200,{'outcome':'sent'})
        assert upstream.calls=={CALL:1,LATE:1}
        print('CONFIRMED LIMITATION: revocation after final status read can still reach synthetic provider',flush=True)
        print('PASS: real Unix peer UID and claim-bound fixture catalog deny spoofing, wrong peer and stale task; one concurrent provider send',flush=True)
    finally:
        upstream.release.set()
        for server in servers:server.resume.set();server.late_resume.set()
        for server,t in reversed(threads):server.shutdown();server.server_close();t.join(timeout=5)
        for server in servers:
            if server not in [s for s,_ in threads]:server.server_close()
        for socket_path in (path,wrong_path):
            try:os.unlink(socket_path)
            except FileNotFoundError:pass
        owned.cleanup()
