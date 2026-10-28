#!/usr/bin/env python3
"""Disposable same-object lease/inference ordering experiment; no provider dispatch."""
import concurrent.futures
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request


def post(url, body):
    request=urllib.request.Request(url,data=json.dumps(body).encode(),method='POST',headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=5) as response:
            data=response.read();return response.status,json.loads(data) if data else None
    except urllib.error.HTTPError as error:return error.code,None


def exercise(base):
    now=int(time.time()*1000)
    lease={'worker_id':'fixture-worker','token':'01ARZ3NDEKTSV4RRFFQ69G5FAV','attempt':1,'issued_ms':now-1000,'expires_ms':now+299000}
    call={'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','request_digest':'a'*64,'review_digest':'b'*64,'model':'fixture-model','amount_microusd':250000,'worker_id':lease['worker_id'],'token':lease['token'],'attempt':1}
    def endpoint(key):return base+'/restate/call/AtomicInferenceFixture/'+key
    for key in ['atomic-revoke-first','atomic-begin-first','atomic-race','atomic-lost','atomic-cap']:
        assert post(endpoint(key)+'/initialize',lease)[0]==200
        assert post(endpoint(key)+'/prepare',call)==(200,'Reserved')
        assert post(endpoint(key)+'/prepare',call)==(200,'Reserved')
        assert post(endpoint(key)+'/prepare',{**call,'request_digest':'c'*64})[0]==409
        assert post(endpoint(key)+'/begin',{**call,'token':'01ARZ3NDEKTSV4RRFFQ69G5FAX'})[0]==403
    first=endpoint('atomic-revoke-first')
    assert post(first+'/revoke',lease)[0]==200
    assert post(first+'/begin',call)[0]==409
    assert post(first+'/inspect',call)==(200,'Reserved')
    assert post(first+'/initialize',lease)[0]==200  # idempotent initialization cannot clear revoke
    assert post(first+'/prepare',call)[0]==409
    assert post(first+'/begin',call)[0]==409
    second=endpoint('atomic-begin-first')
    assert post(second+'/begin',call)[0]==200
    assert post(second+'/revoke',lease)[0]==200
    assert post(second+'/begin',call)[0]==409
    assert post(second+'/inspect',call)==(200,'DispatchingUnknown')
    race=endpoint('atomic-race')
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        begin=pool.submit(post,race+'/begin',call);revoke=pool.submit(post,race+'/revoke',lease)
        begin_code=begin.result()[0];assert revoke.result()[0]==200
    assert begin_code in (200,409),begin_code
    race_stage='DispatchingUnknown' if begin_code==200 else 'Reserved'
    assert post(race+'/inspect',call)==(200,race_stage)
    assert post(race+'/begin',call)[0]==409
    lost=endpoint('atomic-lost');encoded=json.dumps(call).encode();parsed=urllib.parse.urlsplit(base)
    with socket.create_connection((parsed.hostname,parsed.port),timeout=5) as wire:
        wire.sendall(b'POST /restate/call/AtomicInferenceFixture/atomic-lost/begin HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(encoded)).encode()+b'\r\n\r\n'+encoded)
        assert wire.recv(1)==b'H'
    assert post(lost+'/revoke',lease)[0]==200
    assert post(lost+'/begin',call)[0]==409
    assert post(lost+'/inspect',call)==(200,'DispatchingUnknown')
    cap=endpoint('atomic-cap')
    for suffix in ['01ARZ3NDEKTSV4RRFFQ69G5FAX','01ARZ3NDEKTSV4RRFFQ69G5FAY']:
        assert post(cap+'/prepare',{**call,'call_id':suffix})==(200,'Reserved')
    denied={**call,'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAZ','amount_microusd':1}
    assert post(cap+'/prepare',denied)==(200,'Denied')
    assert post(cap+'/begin',denied)[0]==409
    assert post(cap+'/revoke',lease)[0]==200
    print('PASS: same-object revocation/begin ordering, bindings, budget and lost acknowledgement',flush=True)
    return {'lease':lease,'call':call,'race_stage':race_stage}


def verify(base,checkpoint):
    call=checkpoint['call']
    for key,stage in [('atomic-revoke-first','Reserved'),('atomic-begin-first','DispatchingUnknown'),('atomic-race',checkpoint['race_stage']),('atomic-lost','DispatchingUnknown')]:
        endpoint=base+'/restate/call/AtomicInferenceFixture/'+key
        assert post(endpoint+'/inspect',call)==(200,stage)
        assert post(endpoint+'/begin',call)[0]==409
