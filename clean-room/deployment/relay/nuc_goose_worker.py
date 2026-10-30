#!/usr/bin/env python3
"""Fixed credential-free Linux Goose shim. Root launcher and relay are required."""
import base64,http.server,json,os,pathlib,socket,subprocess,sys,tempfile,threading,time
import selectors,stat
REQUEST_FRAME_BYTES=65536
RELAY_REPLY_BYTES=12*1024*1024
RAW_SSE_BYTES=8*1024*1024
RELAY_READ_TIMEOUT_SECONDS=90
def reply_fits(value):return type(value) is int and 0<=value<=RELAY_REPLY_BYTES
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
    mode='write_files'
    while True:
        raw=sys.stdin.buffer.readline(LIMIT+1)
        if not raw:return 0
        if len(raw)>LIMIT or not raw.endswith(b'\n'):return 1
        try:
            q=json.loads(raw,object_pairs_hook=no_duplicates);method=q.get('method');ident=q.get('id')
            if ident is None:continue
            params=q.get('params',{})
            if method=='initialize':result={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'factory-shell-fixture','version':'0.0.1'}}
            elif method=='tools/list':
                tool={'name':'write_files','description':'Write the two authorized task files without executing code.','inputSchema':WRITE_SCHEMA}
                result={'tools':[tool]}
            elif method=='tools/call' and params.get('name')==mode:
                value=relay({'type':'tool','arguments':params.get('arguments')})
                result={'content':[{'type':'text','text':value}],'isError':json.loads(value).get('status')!='executed' or json.loads(value).get('exit_code')!=0}
            else:raise ValueError('unsupported')
            print(json.dumps({'jsonrpc':'2.0','id':ident,'result':result},separators=(',',':')),flush=True)
        except (OSError,ValueError,TypeError):return 1
    return 0

def protected_prompt():
    fd=os.open('/factory/prompt.txt',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o444 or not 0<st.st_size<=32768:raise RuntimeError('prompt unavailable')
        raw=os.read(fd,32769)
        if len(raw)!=st.st_size:raise RuntimeError('prompt unavailable')
        return raw.decode('utf-8')
    finally:os.close(fd)


def run_bounded(args,env):
    p=subprocess.Popen(args,cwd='/work/task',env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector();count=0;deadline=time.monotonic()+150
    try:
        for file in (p.stdout,p.stderr):
            os.set_blocking(file.fileno(),False);selector.register(file,selectors.EVENT_READ)
        while selector.get_map():
            left=deadline-time.monotonic()
            if left<=0:raise RuntimeError('worker deadline exceeded')
            for key,_ in selector.select(left):
                data=os.read(key.fd,65536)
                if not data:selector.unregister(key.fileobj);continue
                count+=len(data)
                if count>1024*1024:raise RuntimeError('worker output exceeded')
        if p.wait(timeout=max(.01,deadline-time.monotonic()))!=0:raise RuntimeError('Goose failed')
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=5)
        selector.close();p.stdout.close();p.stderr.close()


def main():
    if os.getuid()!=2001 or os.geteuid()!=2001:raise RuntimeError('worker identity unavailable')
    prompt=protected_prompt()
    for name in ('task','home','goose/config','goose/data','goose/state'):
        pathlib.Path('/work',name).mkdir(parents=True,exist_ok=True)
    pathlib.Path('/work/goose/config/config.yaml').write_text('{}\n')
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),HttpShim)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/work/home','TMPDIR':'/work','GOOSE_PATH_ROOT':'/work/goose',
         'GOOSE_PROVIDER':'openai','GOOSE_MODEL':'gpt-4o-mini','OPENAI_HOST':'http://127.0.0.1:'+str(server.server_port),
         'OPENAI_BASE_PATH':'v1/chat/completions','OPENAI_API_KEY':'factory-relay-no-provider-secret',
         'GOOSE_DISABLE_SESSION_NAMING':'true','GOOSE_TELEMETRY_ENABLED':'false','GOOSE_MODE':'auto','GOOSE_STATE_MACHINE':'0','PYTHONNOUSERSITE':'1'}
    try:
        run_bounded(['/goose','run','--no-profile','--no-session','--max-turns','3','--output-format','stream-json',
                     '--with-extension','factory:/usr/local/bin/python3 -I -B /factory/nuc_goose_worker.py --mcp',
                     '--text',prompt,'--factory-restricted'],env)
    finally:server.shutdown();server.server_close();thread.join(timeout=5)
    print('{"goose_exit":0}',flush=True)


if __name__=='__main__':
    try:sys.exit(mcp() if sys.argv==[sys.argv[0],'--mcp'] else main() if sys.argv==[sys.argv[0]] else 1)
    except Exception:
        print('worker unavailable',file=sys.stderr);sys.exit(1)
