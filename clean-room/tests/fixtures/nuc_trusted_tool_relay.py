#!/usr/bin/env python3
"""NUC disposable peer/actual execution proof, not production or journal integration."""
import json, os, pathlib, socket, struct, subprocess, tempfile, threading, time, urllib.error, urllib.request, uuid
from trusted_tool_relay import ToolRelay, Refused
IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
EXEC='/tmp/sfactory-gate-linux.X4ZjF1LB/goose-build/execution-target/debug/execution'

def docker(*args, **kw):
    return subprocess.run(['docker',*args], check=True, capture_output=True, timeout=25, **kw)

def post(url, value):
    request=urllib.request.Request(url, data=json.dumps(value,separators=(',',':')).encode(), headers={'content-type':'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(request,timeout=8) as response:
            body=response.read(65537)
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        return error.code,None

def main():
    assert os.getuid()==1000 and pathlib.Path(EXEC).is_file()
    assert docker('image','inspect','--format','{{.Id}}',IMAGE).stdout.decode().strip()==IMAGE
    token=uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='sfactory-tool-relay-',dir='/tmp') as root:
        root=pathlib.Path(root);root.chmod(0o711)
        policy=root/'policy.toml';policy.write_text('blocked_binaries = ["dd"]\nwrite_commands = ["rm", "mv", "cp", "chmod", "tee"]\nallowed_write_paths = ["/work"]\n');policy.chmod(0o444)
        sock=root/'gate.sock';listener=socket.socket(socket.AF_UNIX);listener.bind(str(sock));sock.chmod(0o666);listener.listen(4);listener.settimeout(20)
        name='sfactory-tool-exec-'+token
        def execute(args):
            try:
                result=docker('run','-i','--name',name,'--label','sfactory.fixture='+token,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','24','--memory','96m','--cpus','0.5','--user','1001:1001','--tmpfs','/work:rw,nosuid,nodev,size=16m,mode=1777','--workdir','/work','--mount','type=bind,src='+EXEC+',dst=/execution,readonly','--mount','type=bind,src='+str(policy)+',dst=/policy,readonly','--env','SFACTORY_POLICY=/policy','--entrypoint','/execution','--pull','never',IMAGE,'--tool-request',input=json.dumps(args).encode())
                return json.loads(result.stdout)
            finally:
                subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        relay=ToolRelay(execute);relay.record_provider_call('synthetic-provider-1',{'command':'printf RELAY_OK'})
        journal=os.environ.get('SFACTORY_FIXTURE_JOURNAL')
        if journal:
            now=int(time.time()*1000)
            lease={'worker_id':'fixture-worker','token':'01ARZ3NDEKTSV4RRFFQ69G5FAV','attempt':1,'issued_ms':now-1000,'expires_ms':now+299000}
            tool={'type':'function','function':{'name':'factory__shell','parameters':{'type':'object'}}}
            initial={'model':'auto','messages':[{'role':'system','content':'system'},{'role':'user','content':'task'}],'tools':[tool],'max_tokens':100,'stream':True,'stream_options':{'include_usage':True}}
            raw=lambda v:list(json.dumps(v,separators=(',',':')).encode())
            def route(name,rate):return {'model':name,'review_digest':'a'*64,'reviewed_at_ms':now-1000,'valid_until_ms':now+299000,'input_microusd_per_million':rate,'output_microusd_per_million':rate,'max_billable_input_tokens':1000000,'max_billable_output_tokens':1000000,'fixed_call_microusd':0,'max_request_bytes':65536,'output_limit_field':'max_tokens'}
            spec={'lease':lease,'initial':raw(initial),'tool':tool,'max_tokens':100,'routes':[route('fixture-cheap',100),route('fixture-expensive',200)]}
            first={'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','turn':0,'request':raw(initial)}
            assistant={'role':'assistant','content':None,'tool_calls':[{'id':'synthetic-provider-1','type':'function','function':{'name':'factory__shell','arguments':'{"command":"printf RELAY_OK"}'}}]}
            assert post(journal+'/initialize',spec)[0]==200
            assert post(journal+'/prepare',first)==(200,True)
            assert post(journal+'/begin',first)==(200,True)
        seen=[]
        def serve():
            for _ in range(4):
                c,_=listener.accept()
                with c:
                    c.settimeout(5)
                    _,uid,_=struct.unpack('3i',c.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if uid!=1001:
                        seen.append(('denied-peer',uid));c.sendall(b'denied\n');continue
                    data=b''
                    while b'\n' not in data and len(data)<=65536:
                        part=c.recv(4096)
                        if not part:break
                        data+=part
                    try:
                        if len(data)>65536 or not data.endswith(b'\n'):raise Refused('invalid frame')
                        request=json.loads(data)
                        if set(request)!={'id','arguments'}:raise Refused('invalid request')
                        result=relay.call(request['id'],request['arguments'])
                        if journal:assert post(journal+'/bind',{'call_id':first['call_id'],'assistant':assistant,'tool_result':result})==(200,True)
                        seen.append(('ok',result))
                        c.sendall((json.dumps(result,separators=(',',':'))+'\n').encode())
                    except (ValueError, Refused):seen.append(('denied-call',uid));c.sendall(b'denied\n')
        thread=threading.Thread(target=serve);thread.start()
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(sock));assert client.recv(100)==b'denied\n'
        client_code='import json,socket; s=socket.socket(socket.AF_UNIX);s.connect("/gate/gate.sock");s.sendall((json.dumps({"id":"synthetic-provider-1","arguments":{"command":"printf RELAY_OK"}})+"\\n").encode());print(s.recv(65536).decode())'
        common=['run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','24','--memory','96m','--cpus','0.5','--user','1001:1001','--mount','type=bind,src='+str(root)+',dst=/gate,readonly','--entrypoint','python3','--pull','never',IMAGE,'-c',client_code]
        unrelated=common.copy();unrelated[unrelated.index('1001:1001')]='1002:1002'
        assert docker(*unrelated).stdout.strip()==b'denied'
        first=docker(*common).stdout.decode();second=docker(*common).stdout.decode()
        thread.join(20);listener.close();assert not thread.is_alive()
        print('synthetic response:',first.strip(),flush=True)
        assert json.loads(first)['content']==json.dumps({'status':'executed','exit_code':0,'stdout':'RELAY_OK','stderr':''},separators=(',',':'))
        if journal:
            captured=seen[2][1]
            continuation={**initial,'messages':initial['messages']+[assistant,captured]}
            admission={'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAX','turn':1,'request':raw(continuation)}
            forged={**captured,'content':'forged'}
            forged_admission={**admission,'request':raw({**initial,'messages':initial['messages']+[assistant,forged]})}
            assert post(journal+'/prepare',forged_admission)[0]==403
            assert post(journal+'/prepare',admission)==(200,True)
            assert post(journal+'/begin',admission)==(200,True)
            assert post(journal+'/begin',admission)[0]==409
            print('PASS: captured actual isolated execution reply bound to disposable Restate; forged continuation and replay denied')
        assert second.strip()=='denied' and seen[0][0]=='denied-peer' and seen[1]==('denied-peer',1002) and seen[2][0]=='ok' and seen[3][0]=='denied-call'
        print('PASS: kernel UIDs 1000 and 1002 denied; UID1001 synthetic call executed once in network-none container and replay denied')

if __name__=='__main__':main()
