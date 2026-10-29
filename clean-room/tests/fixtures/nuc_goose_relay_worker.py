#!/usr/bin/env python3
"""Network-none Goose client shim for synthetic service-owned relay. No credentials."""
import base64,http.server,json,os,pathlib,socket,subprocess,sys,tempfile,threading,time
from nuc_stream_contract import REQUEST_FRAME_BYTES,RELAY_REPLY_BYTES,reply_fits,RAW_SSE_BYTES,RELAY_READ_TIMEOUT_SECONDS
SOCKET='/gate/relay.sock';LIMIT=REQUEST_FRAME_BYTES
WRITE_SCHEMA={'type':'object','properties':{'files':{'type':'object','properties':{'hello.py':{'type':'string','maxLength':8192},'test_hello.py':{'type':'string','maxLength':8192}},'required':['hello.py','test_hello.py'],'additionalProperties':False}},'required':['files'],'additionalProperties':False}

def no_duplicates(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError('duplicate key')
        value[key]=item
    return value

def relay(payload):
    raw=json.dumps(payload,separators=(',',':')).encode()
    if len(raw)>LIMIT:raise ValueError('oversized request')
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(RELAY_READ_TIMEOUT_SECONDS);s.connect(SOCKET);s.sendall(raw+b'\n');parts=[];size=0
        while True:
            chunk=s.recv(4096)
            if not chunk:break
            size+=len(chunk)
            if not reply_fits(size):raise ValueError('oversized response')
            parts.append(chunk)
        reply=json.loads(b''.join(parts))
        if not isinstance(reply,dict) or set(reply)!={'ok','value'} or reply['ok'] is not True:raise ValueError('relay rejected')
        return reply['value']

class HttpShim(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length=int(self.headers.get('Content-Length','0'))
            if self.path!='/v1/chat/completions' or not 0<length<=LIMIT:raise ValueError('invalid request')
            body=json.loads(self.rfile.read(length),object_pairs_hook=no_duplicates);raw=base64.b64decode(relay({'type':'inference','body':body}),validate=True)
            if len(raw)>RAW_SSE_BYTES:raise ValueError('oversized response')
            self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        except (OSError,ValueError,TypeError):self.send_error(502)
    def log_message(self,*_):pass

def mcp():
    mode=os.environ.get('SFACTORY_TOOL_MODE','shell')
    if mode not in ('shell','write_files'):return 1
    for raw in sys.stdin.buffer:
        if len(raw)>LIMIT:return 1
        try:
            q=json.loads(raw,object_pairs_hook=no_duplicates);method=q.get('method');ident=q.get('id')
            if ident is None:continue
            params=q.get('params',{})
            if method=='initialize':result={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'factory-shell-fixture','version':'0.0.1'}}
            elif method=='tools/list':
                tool={'name':'write_files','description':'Write the two authorized task files without executing code.','inputSchema':WRITE_SCHEMA} if mode=='write_files' else {'name':'shell','description':'Run a policy-checked command in the trusted task directory; output is bounded and masked.','inputSchema':{'type':'object','properties':{'command':{'type':'string','maxLength':16384}},'required':['command'],'additionalProperties':False}}
                result={'tools':[tool]}
            elif method=='tools/call' and params.get('name')==mode:
                value=relay({'type':'tool','arguments':params.get('arguments')})
                result={'content':[{'type':'text','text':value}],'isError':json.loads(value).get('status')!='executed' or json.loads(value).get('exit_code')!=0}
            else:raise ValueError('unsupported')
            print(json.dumps({'jsonrpc':'2.0','id':ident,'result':result},separators=(',',':')),flush=True)
        except (OSError,ValueError,TypeError):return 1
    return 0

def main():
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),HttpShim);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='goose-relay-',dir='/work') as tmp:
            root=pathlib.Path(tmp);goose=root/'goose';home=root/'home';work=root/'work'
            for p in (goose/'config',goose/'data',goose/'state',home,work):p.mkdir(parents=True)
            (goose/'config/config.yaml').write_text('{}\n')
            env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(home),'TMPDIR':str(root),'GOOSE_PATH_ROOT':str(goose),'GOOSE_PROVIDER':'openai','GOOSE_MODEL':'gpt-4o-mini','OPENAI_HOST':'http://127.0.0.1:%s'%server.server_address[1],'OPENAI_BASE_PATH':'v1/chat/completions','OPENAI_API_KEY':'offline-fixture-not-a-credential','GOOSE_DISABLE_SESSION_NAMING':'true','GOOSE_TELEMETRY_ENABLED':'false','GOOSE_MODE':'auto','GOOSE_STATE_MACHINE':'0','PYTHONNOUSERSITE':'1','SFACTORY_TOOL_MODE':os.environ.get('SFACTORY_TOOL_MODE','shell')}
            extension='factory:/usr/local/bin/python3 /fixtures/nuc_goose_relay_worker.py --mcp'
            prompt=os.environ.get('SFACTORY_TASK_PROMPT','Offline fixture: call the factory tool requested by the provider.')
            if not prompt or len(prompt.encode())>32768:raise RuntimeError('task unavailable')
            p=subprocess.run(['/goose','run','--no-profile','--no-session','--max-turns','3','--output-format','stream-json','--with-extension',extension,'--text',prompt,'--factory-restricted'],cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=150 if os.environ.get('SFACTORY_LIVE_TASK')=='1' else 60)
            if p.returncode!=0 or (os.environ.get('SFACTORY_LIVE_TASK')!='1' and b'OFFLINE_FACTORY_DONE' not in p.stdout):
                if os.environ.get('SFACTORY_DIAGNOSTICS')=='1':print('GOOSE_DIAGNOSTIC exit='+str(p.returncode)+' stdout_bytes='+str(len(p.stdout))+' stderr_bytes='+str(len(p.stderr)),flush=True)
                raise RuntimeError('Goose fixture failed')
            print('PASS: Linux Goose completed host-relay tool exchange',flush=True)
            if os.environ.get('SFACTORY_FIXTURE_HOLD')=='1':
                print('FIXTURE_WORKER_HOLD',flush=True)
                time.sleep(90)
    finally:server.shutdown();server.server_close();thread.join(timeout=5)

if __name__=='__main__':sys.exit(mcp() if '--mcp' in sys.argv else main())
