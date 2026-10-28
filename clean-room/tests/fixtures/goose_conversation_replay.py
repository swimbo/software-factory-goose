#!/usr/bin/env python3
"""Actual Goose synthetic tool exchange through fresh Restate fixture, not production authorization."""
import http.server,json,os,pathlib,sys,threading,time,urllib.request,uuid
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT.parent/'docs/planning/clean-room/verification'))
import goose_factory_boundary_spike as original
import goose_gateway_protocol_spike as protocol
from atomic_inference_fixture import post

EXPECTED={
 './allowed':{'status':'executed','exit_code':0,'stdout':'VISIBLE_ALLOWED','stderr':''},
 './dd':{'status':'refused','reason':'policy_denied'},
 './emit-secret':{'status':'executed','exit_code':7,'stdout':'[REDACTED]','stderr':'[REDACTED]'},
 './invalid-output':{'status':'refused','reason':'output_withheld'},
}
def checked(url, payload, expected, label):
 result=post(url,payload)
 if result!=expected:raise ValueError(f'{label}: {result}')

def expected(args):
 if set(args)!={'command'}:return {'status':'refused','reason':'invalid_request'}
 return EXPECTED.get(args['command'],{'status':'refused','reason':'policy_denied'})

class JournalProxy(original.Stub):
 def do_POST(self):
  try:
   size=int(self.headers.get('Content-Length','-1'))
   if self.path!='/v1/chat/completions' or not 0<size<=65536:raise ValueError('route/size')
   raw=self.rfile.read(size);body=json.loads(raw)
   if not protocol.valid_request(body):raise ValueError('unreviewed request')
   # This bootstrap is trusted synthetic fixture configuration, not task provenance.
   routed={**body,'model':'auto'}; encoded=list(json.dumps(routed,separators=(',',':')).encode())
   messages=body['messages']; first=len(messages)==2
   if first:
    now=int(time.time()*1000)
    lease={'worker_id':'fixture-worker','token':'01ARZ3NDEKTSV4RRFFQ69G5FAV','attempt':1,'issued_ms':now-1000,'expires_ms':now+299000}
    def route(name,rate):return {'model':name,'review_digest':'a'*64,'reviewed_at_ms':now-1000,'valid_until_ms':now+299000,'input_microusd_per_million':rate,'output_microusd_per_million':rate,'max_billable_input_tokens':1000000,'max_billable_output_tokens':1000000,'fixed_call_microusd':0,'max_request_bytes':65536,'output_limit_field':'max_tokens'}
    spec={'lease':lease,'initial':encoded,'tool':body['tools'][0],'max_tokens':16384,'routes':[route('fixture-cheap',100),route('fixture-expensive',200)]}
    self.server.journal=self.server.base+'/restate/call/ConversationFixture/goose-'+uuid.uuid4().hex
    checked(self.server.journal+'/initialize',spec,(200,None),'initialize')
   elif len(messages)==4:
    x={'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','assistant':self.server.assistant,'tool_result':{'role':'tool','tool_call_id':self.server.tool_id,'content':json.dumps(expected(self.server.arguments),separators=(',',':'))}}
    checked(self.server.journal+'/bind',x,(200,True),'bind')
   else:raise ValueError('sequence')
   admission={'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW' if first else '01ARZ3NDEKTSV4RRFFQ69G5FAX','turn':0 if first else 1,'request':encoded}
   checked(self.server.journal+'/prepare',admission,(200,True),'prepare')
   checked(self.server.journal+'/begin',admission,(200,True),'begin')
   self.server.reservations+=1
   self.server.records.append({'path':self.path,'body':body})
   self.server.upstream.arguments=self.server.arguments
   request=urllib.request.Request(self.server.upstream_url,data=raw,headers={'Content-Type':'application/json'},method='POST')
   with urllib.request.urlopen(request,timeout=5) as response:
    data=response.read(65537)
    if response.status!=200 or len(data)>65536 or not protocol.valid_sse(data):raise ValueError('invalid synthetic response')
   if first:
    chunk=json.loads(data.decode().split('\n\n')[0][6:]);delta=chunk['choices'][0]['delta']
    call=dict(delta['tool_calls'][0]);call.pop('index');self.server.tool_id=call['id']
    # Goose parses and reserializes tool arguments; derive normalization from the provider response.
    call['function']['arguments']=json.dumps(json.loads(call['function']['arguments']),separators=(',',':'),ensure_ascii=False)
    self.server.assistant={'role':'assistant','content':None,'tool_calls':[call]}
   self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
  except Exception as e:
   print('journal fixture rejected:',type(e).__name__,str(e),file=sys.stderr,flush=True);self.send_error(502)


def exercise(base, goose, execution, summary):
 upstream=http.server.ThreadingHTTPServer(('127.0.0.1',0),original.FactoryStub);upstream.records=[]
 thread=threading.Thread(target=upstream.serve_forever,daemon=True);thread.start()
 observed=[];old_server=original.http.server.ThreadingHTTPServer
 def factory(address,handler):
  server=old_server(address,JournalProxy);server.base=base;server.reservations=0;server.upstream=upstream
  server.upstream_url='http://127.0.0.1:%d/v1/chat/completions'%upstream.server_address[1];observed.append(server);return server
 old_argv=sys.argv; original.http.server.ThreadingHTTPServer=factory;original.FactoryStub=JournalProxy
 sys.argv=['fixture','--goose',str(goose),'--sha256','512bc701fca7312be12ae03215a41a0a60fae0848e2c39f167b7f79e510658fb','--execution',str(execution),'--factory-restricted','--summary',str(summary)]
 try:
  status=original.main();assert status==0 and observed[0].reservations==12 and len(upstream.records)==12
  print('PASS: actual Goose six tool conversations passed a synthetic single-object Restate journal; fixture bootstrap/exchange trusted',flush=True)
 finally:
  sys.argv=old_argv;original.http.server.ThreadingHTTPServer=old_server;upstream.shutdown();upstream.server_close();thread.join(timeout=5)
