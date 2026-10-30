#!/usr/bin/env python3
"""Offline protected-Goose entry canary. No provider credentials or host effects."""
import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading

SCHEMA = {'type':'object','properties':{'files':{'type':'object','properties':{'hello.py':{'type':'string','maxLength':8192},'test_hello.py':{'type':'string','maxLength':8192}},'required':['hello.py','test_hello.py'],'additionalProperties':False}},'required':['files'],'additionalProperties':False}
ARGS = {'files':{'hello.py':'print("offline")\n','test_hello.py':'assert True\n'}}


def mcp():
    # readline's bound applies before parsing or allocating an entire frame.
    while True:
        raw = sys.stdin.buffer.readline(65537)
        if not raw: return
        if len(raw)>65536 or not raw.endswith(b'\n'): raise RuntimeError('frame unavailable')
        q=json.loads(raw); ident=q.get('id'); method=q.get('method')
        if ident is None: continue
        if method=='initialize':
            result={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'offline-protected-canary','version':'1'}}
        elif method=='tools/list':
            result={'tools':[{'name':'write_files','description':'Write the two authorized task files without executing code.','inputSchema':SCHEMA}]}
        elif method=='tools/call' and q.get('params',{}).get('name')=='write_files' and q['params'].get('arguments')==ARGS:
            marker=pathlib.Path('/work/tool-called')
            with marker.open('x') as f: f.write('offline-only\n')
            result={'content':[{'type':'text','text':'{"status":"executed","exit_code":0}'}],'isError':False}
        else: raise RuntimeError('method unavailable')
        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':result}),flush=True)


def sse(delta,finish):
    common={'id':'offline','object':'chat.completion.chunk','created':1,'model':'gpt-4o-mini'}
    chunks=[{**common,'choices':[{'index':0,'delta':delta,'finish_reason':None}]},
            {**common,'choices':[{'index':0,'delta':{},'finish_reason':finish}],
             'usage':{'prompt_tokens':10,'completion_tokens':4,'total_tokens':14}}]
    return (''.join('data: '+json.dumps(c)+'\n\n' for c in chunks)+'data: [DONE]\n\n').encode()


def main():
    requests=[]; errors=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length=int(self.headers.get('Content-Length','0'))
                if self.path!='/v1/chat/completions' or not 0<length<=65536: raise ValueError('request unavailable')
                body=json.loads(self.rfile.read(length)); requests.append(body)
                if len(requests)==1:
                    if pathlib.Path('/work/tool-called').exists(): raise ValueError('early tool')
                    call={'id':'offline-protected-call','type':'function','function':{'name':'factory__write_files','arguments':json.dumps(ARGS,separators=(',',':'))}}
                    raw=sse({'role':'assistant','tool_calls':[{'index':0,**call}]},'tool_calls')
                elif len(requests)==2 and pathlib.Path('/work/tool-called').read_text()=='offline-only\n':
                    raw=sse({'role':'assistant','content':'OFFLINE_FACTORY_DONE'},'stop')
                else: raise ValueError('exchange unavailable')
                self.send_response(200); self.send_header('Content-Type','text/event-stream'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
            except Exception as exc:
                errors.append(type(exc).__name__); self.send_error(502)
        def log_message(self,*args): pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    for name in ('task','home','goose/config','goose/data','goose/state'):
        pathlib.Path('/work',name).mkdir(parents=True,exist_ok=True)
    pathlib.Path('/work/goose/config/config.yaml').write_text('{}\n')
    env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/work/home','TMPDIR':'/work','GOOSE_PATH_ROOT':'/work/goose',
         'GOOSE_PROVIDER':'openai','GOOSE_MODEL':'gpt-4o-mini','OPENAI_HOST':'http://127.0.0.1:'+str(server.server_port),
         'OPENAI_BASE_PATH':'v1/chat/completions','OPENAI_API_KEY':'factory-relay-no-provider-secret',
         'GOOSE_DISABLE_SESSION_NAMING':'true','GOOSE_TELEMETRY_ENABLED':'false','GOOSE_MODE':'auto','GOOSE_STATE_MACHINE':'0','PYTHONNOUSERSITE':'1'}
    try:
        p=subprocess.run(['/goose','run','--no-profile','--no-session','--max-turns','3','--output-format','stream-json',
                          '--with-extension','factory:/usr/local/bin/python3 /canary.py --mcp',
                          '--text','Offline fixture: call the factory write_files tool requested by the provider.','--factory-restricted'],
                         cwd='/work/task',env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=65)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)
    negative=len(sys.argv)==2 and sys.argv[1]=='negative'
    if negative:
        assert p.returncode!=0 and not requests and not pathlib.Path('/work/tool-called').exists(), 'negative control admitted effects'
    else:
        assert p.returncode==0 and len(requests)==2 and not errors and b'OFFLINE_FACTORY_DONE' in p.stdout, 'positive exchange failed: '+p.stderr[-4000:].decode(errors='replace')
    # Public offline captures support exact initial-envelope normalization review.
    print(json.dumps({'offline_only':True,'negative':negative,'goose_exit':p.returncode,'inference_requests':len(requests),
                      'tool_called':pathlib.Path('/work/tool-called').exists(),'requests':requests,
                      'stderr':p.stderr[-4000:].decode(errors='replace')},sort_keys=True))


if __name__=='__main__':
    mcp() if '--mcp' in sys.argv else main()
