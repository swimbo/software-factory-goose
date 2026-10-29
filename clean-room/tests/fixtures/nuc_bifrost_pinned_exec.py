#!/usr/bin/env python3
"""Task-only pinned Docker exec transport. No invocation or route is registered."""
import http.client,io,json,os,re,selectors,stat,subprocess,tempfile,time
from nuc_bifrost_live_transport import _open_anchored,TransportRefused,MAX_REQUEST,MAX_RESPONSE
from nuc_stream_contract import PROVIDER_WIRE_BYTES

class MemorySocket:
 def __init__(self,data):self.stream=io.BytesIO(data)
 def makefile(self,*_args,**_kw):return self.stream

def valid_http_headers(raw):
 if not isinstance(raw,bytes) or b'\r\n\r\n' not in raw:return False
 lines=raw.split(b'\r\n\r\n',1)[0].split(b'\r\n');seen=set()
 for line in lines[1:]:
  if b':' not in line or line[:1] in (b' ',b'\t'):return False
  name,value=line.split(b':',1);name=name.lower();value=value.strip().lower()
  if name==b'content-length' and (not value.isdigit() or len(value)>10):return False
  if name==b'transfer-encoding' and value!=b'chunked':return False
  if name in (b'content-length',b'transfer-encoding'):
   if name in seen:return False
   seen.add(name)
 return not (b'content-length' in seen and b'transfer-encoding' in seen)

def response_metadata(raw):
 result={'wire_bytes':len(raw),'framing_complete':complete_http(raw),'version':'unavailable','status':None,'content_type':'unavailable','content_length':None,'transfer_encoding':'unavailable'}
 try:
  response=http.client.HTTPResponse(MemorySocket(raw));response.begin()
  result['version']={10:'1.0',11:'1.1'}.get(response.version,'other');result['status']=response.status if 100<=response.status<=599 else None
  content=response.getheader('Content-Type','').split(';',1)[0].strip().lower()
  result['content_type']=content if content in ('text/event-stream','application/json','text/plain') else 'other'
  length=response.getheader('Content-Length','')
  if length.isascii() and length.isdigit() and len(length)<=10:result['content_length']=int(length)
  transfer=response.getheader('Transfer-Encoding','').strip().lower()
  result['transfer_encoding']=transfer if transfer in ('','chunked') else 'other'
 except (OSError,ValueError,http.client.HTTPException):pass
 return result

def parse_http(raw):
 if not isinstance(raw,bytes) or len(raw)>PROVIDER_WIRE_BYTES or not valid_http_headers(raw):raise TransportRefused('provider outcome unknown')
 try:
  response=http.client.HTTPResponse(MemorySocket(raw));response.begin()
  content_type=response.getheader('Content-Type','').split(';',1)[0].strip().lower()
  kind=content_type if content_type in ('text/event-stream','application/json') else 'other'
  request_id=response.getheader('x-request-id','')
  if not re.fullmatch(r'[A-Fa-f0-9-]{16,64}',request_id):request_id='unavailable'
  if response.status!=200 or content_type!='text/event-stream':
   code='unavailable';category='unavailable';choices='unavailable'
   if content_type=='application/json':
    try:
     body=response.read(65537)
     if len(body)<=65536:
      value=json.loads(body);choices=isinstance(value,dict) and 'choices' in value
      error=value.get('error') if isinstance(value,dict) else None
      if isinstance(error,dict):
       allowed={'invalid_request_error','authentication_error','permission_error','rate_limit_error','api_error','invalid_api_key','model_not_found','unsupported_http_version','invalid_request','unauthorized','forbidden','not_found','internal_error'}
       candidate=error.get('code');code=candidate if isinstance(candidate,str) and candidate in allowed else 'other'
       candidate=error.get('type');category=candidate if isinstance(candidate,str) and candidate in allowed else 'other'
    except (ValueError,TypeError,OSError,http.client.HTTPException):pass
   raise TransportRefused(f'provider rejected status={response.status} content_type={kind} request_id={request_id} error_code={code} error_category={category} choices_present={choices}')
  if not complete_http(raw):raise TransportRefused('provider outcome unknown')
  body=response.read(MAX_RESPONSE+1)
  if len(body)>MAX_RESPONSE or response.length not in (None,0):raise TransportRefused('provider outcome unknown')
  return body
 except TransportRefused:raise
 except Exception:raise TransportRefused('provider outcome unknown') from None

def complete_http(raw):
 """Whether a bounded HTTP response is complete while the write side stays open."""
 if not isinstance(raw,bytes) or len(raw)>PROVIDER_WIRE_BYTES or not valid_http_headers(raw):return False
 try:
  response=http.client.HTTPResponse(MemorySocket(raw));response.begin()
  if response.chunked:
   if b'\r\n\r\n' not in raw:return False
   data=raw.split(b'\r\n\r\n',1)[1];position=0;total=0
   while True:
    end=data.find(b'\r\n',position)
    if end<0:return False
    token=data[position:end].split(b';',1)[0]
    if not token or len(token)>16 or any(c not in b'0123456789abcdefABCDEF' for c in token):return False
    size=int(token,16);position=end+2
    if size==0:
     while True:
      end=data.find(b'\r\n',position)
      if end<0:return False
      if end==position:return end+2==len(data)
      if b':' not in data[position:end]:return False
      position=end+2
    total+=size
    if total>MAX_RESPONSE or len(data)<position+size+2 or data[position+size:position+size+2]!=b'\r\n':return False
    position+=size+2
  if response.length is not None:
   length=response.length
   if length>MAX_RESPONSE:return False
   body=raw.split(b'\r\n\r\n',1)[1]
   return len(body)==length
  body=response.read(MAX_RESPONSE+1)
  content=response.getheader('Content-Type','').split(';',1)[0].strip().lower()
  return response.status==200 and content=='text/event-stream' and len(body)<=MAX_RESPONSE and body.replace(b'\r\n',b'\n').endswith(b'data: [DONE]\n\n')
 except (OSError,ValueError,http.client.HTTPException):return False

class IncrementalFramer:
 """Track response framing without repeatedly scanning the accumulated body."""
 def __init__(self):
  self.mode=None;self.position=0;self.total=0;self.size=None;self.done=False;self.invalid=False;self.expected=0
 def feed(self,raw):
  if self.invalid or len(raw)>PROVIDER_WIRE_BYTES:return False
  if self.done:
   if len(raw)!=self.position:self.invalid=True;return False
   return True
  if self.mode is None:
   end=raw.find(b'\r\n\r\n')
   if end<0:
    if len(raw)>65536:self.invalid=True
    return False
   if end>65536 or not valid_http_headers(bytes(raw[:end+4])):self.invalid=True;return False
   try:
    response=http.client.HTTPResponse(MemorySocket(bytes(raw[:end+4])));response.begin()
    self.position=end+4
    if response.chunked:self.mode='chunked'
    elif response.length is not None:
     if response.length>MAX_RESPONSE:self.invalid=True;return False
     self.expected=self.position+response.length;self.mode='length'
    elif response.status==200 and response.getheader('Content-Type','').split(';',1)[0].strip().lower()=='text/event-stream':self.mode='close'
    else:self.invalid=True;return False
   except (OSError,ValueError,http.client.HTTPException):self.invalid=True;return False
  if self.mode=='length':
   if len(raw)>self.expected:self.invalid=True;return False
   if len(raw)==self.expected:self.done=True;self.position=self.expected;return True
   return False
  if self.mode=='close':
   if len(raw)-self.position>MAX_RESPONSE:self.invalid=True;return False
   if raw.endswith(b'data: [DONE]\n\n') or raw.endswith(b'data: [DONE]\r\n\r\n'):
    self.position=len(raw);self.done=True;return True
   return False
  while True:
   if self.mode=='trailers':
    end=raw.find(b'\r\n',self.position)
    if end<0:return False
    if end==self.position:
     self.position=end+2
     if len(raw)!=self.position:self.invalid=True;return False
     self.done=True;return True
    if b':' not in raw[self.position:end]:self.invalid=True;return False
    self.position=end+2;continue
   if self.size is None:
    end=raw.find(b'\r\n',self.position)
    if end<0:
     if len(raw)-self.position>128:self.invalid=True
     return False
    token=bytes(raw[self.position:end]).split(b';',1)[0]
    if not token or len(token)>16 or any(c not in b'0123456789abcdefABCDEF' for c in token):self.invalid=True;return False
    self.size=int(token,16);self.position=end+2
    if self.size==0:self.mode='trailers';self.size=None;continue
    self.total+=self.size
    if self.total>MAX_RESPONSE:self.invalid=True;return False
   if len(raw)<self.position+self.size+2:return False
   if raw[self.position+self.size:self.position+self.size+2]!=b'\r\n':self.invalid=True;return False
   self.position+=self.size+2;self.size=None

class PinnedDockerTransport:
 def __init__(self,*,container_id,image_id,pid,daemon_id,credential_path,trace=None,capture=None):
  if (len(container_id)!=64 or any(c not in '0123456789abcdef' for c in container_id)
      or not image_id.startswith('sha256:') or len(image_id)!=71 or not isinstance(pid,int) or pid<=0 or not isinstance(daemon_id,str) or not daemon_id):raise TransportRefused('provider unavailable')
  self.container_id=container_id;self.image_id=image_id;self.pid=pid;self.daemon_id=daemon_id;self.trace=trace;self.capture=capture
  self._config=tempfile.TemporaryDirectory(prefix='sfactory-docker-config-')
  self._docker=['/usr/bin/docker','--host','unix:///run/docker.sock','--config',self._config.name]
  self._env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'}
  self._identity()
  try:self._credential=_open_anchored(credential_path)
  except OSError:raise TransportRefused('credential unavailable') from None
 def _identity(self):
  try:
   cli=os.stat('/usr/bin/docker',follow_symlinks=False);sock=os.stat('/run/docker.sock',follow_symlinks=False);parent=os.stat('/run',follow_symlinks=False);bin_parent=os.stat('/usr/bin',follow_symlinks=False)
   if not stat.S_ISREG(cli.st_mode) or cli.st_uid!=0 or cli.st_mode & 0o022 or not stat.S_ISSOCK(sock.st_mode) or sock.st_uid!=0 or not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0 or parent.st_mode & 0o022 or not stat.S_ISDIR(bin_parent.st_mode) or bin_parent.st_uid!=0 or bin_parent.st_mode & 0o022:raise TransportRefused('provider unavailable')
   daemon=subprocess.run(self._docker+['info','--format','{{.ID}}'],env=self._env,capture_output=True,timeout=5,check=True)
   if daemon.stdout.decode().strip()!=self.daemon_id:raise TransportRefused('provider unavailable')
   result=subprocess.run(self._docker+['inspect','--format','{{.Id}} {{.Image}} {{.State.Pid}} {{.State.Status}}',self.container_id],env=self._env,capture_output=True,timeout=5,check=True)
   if result.stdout.decode().strip()!=f'{self.container_id} {self.image_id} {self.pid} running':raise TransportRefused('provider unavailable')
  except TransportRefused:raise
  except Exception:raise TransportRefused('provider unavailable') from None
 def send(self,body):
  if not isinstance(body,dict) or body.get('model')!='auto':raise TransportRefused('route unavailable')
  data=json.dumps(body,separators=(',',':'),ensure_ascii=False).encode()
  if len(data)>MAX_REQUEST:raise TransportRefused('request unavailable')
  wire=(b'POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\nConnection: close\r\nx-bf-vk: '+self._credential.encode()+b'\r\nContent-Length: '+str(len(data)).encode()+b'\r\n\r\n'+data)
  raw=self._exchange(wire)
  try:result=parse_http(raw)
  except TransportRefused:
   self._trace('parse_failed',raw);raise
  self._trace('parse_ok',raw)
  capture=getattr(self,'capture',None)
  if capture is not None:
   if self._credential.encode() in result:raise TransportRefused('capture unavailable')
   try:capture(result)
   except Exception:raise TransportRefused('capture unavailable') from None
  return result
 def probe_models(self):
  wire=(b'GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nx-bf-vk: '+self._credential.encode()+b'\r\n\r\n')
  raw=self._exchange(wire)
  try:
   response=http.client.HTTPResponse(MemorySocket(raw));response.begin()
   content=response.getheader('Content-Type','').split(';',1)[0].strip().lower()
   kind=content if content in ('application/json','text/plain') else 'other'
   return {'status':response.status,'content_type':kind}
  except Exception:raise TransportRefused('probe unavailable') from None
 def _trace(self,event,raw,exit_code=None):
  callback=getattr(self,'trace',None)
  if callback is not None:
   metadata=response_metadata(raw);metadata.update(event=event,child_exit=exit_code if isinstance(exit_code,int) and -255<=exit_code<=255 else None);callback(metadata)
 def _exchange(self,wire):
  self._identity()
  process=None;selector=None;out=bytearray();stage='spawn'
  def unknown(category):
   try:framing='complete' if complete_http(bytes(out)) else 'incomplete'
   except Exception:framing='invalid'
   self._trace('failure_'+category,bytes(out),process.poll() if process is not None else None)
   return TransportRefused('provider outcome unknown stage='+category+' response_bytes='+str(len(out))+' framing='+framing)
  try:
   process=subprocess.Popen(self._docker+['exec','-i',self.container_id,'/usr/bin/nc','-w','60','127.0.0.1','8080'],env=self._env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,bufsize=0)
   stage='setup';selector=selectors.DefaultSelector();os.set_blocking(process.stdin.fileno(),False);os.set_blocking(process.stdout.fileno(),False)
   selector.register(process.stdin,selectors.EVENT_WRITE);selector.register(process.stdout,selectors.EVENT_READ)
   pending=memoryview(wire);deadline=time.monotonic()+65;framer=IncrementalFramer()
   while selector.get_map():
    remaining=deadline-time.monotonic()
    if remaining<=0:raise unknown('deadline')
    events=selector.select(min(remaining,1))
    for key,_ in events:
     if key.fileobj is process.stdin:
      stage='write';count=os.write(process.stdin.fileno(),pending[:16384]);pending=pending[count:]
      if not pending:selector.unregister(process.stdin)
     else:
      stage='read';chunk=os.read(process.stdout.fileno(),16384)
      if not chunk:selector.unregister(process.stdout);process.stdout.close();continue
      out.extend(chunk)
      if len(out)>PROVIDER_WIRE_BYTES:raise unknown('response_limit')
      if not pending and not process.stdin.closed:
       ready=framer.feed(out)
       if framer.invalid:raise unknown('framing_invalid')
       if ready:
        if not complete_http(bytes(out)):raise unknown('framing_invalid')
        self._trace('framing_complete_before_close',bytes(out));process.stdin.close()
   stage='child_exit'
   exit_code=process.wait(timeout=max(.1,deadline-time.monotonic()));self._trace('child_exit',bytes(out),exit_code)
   if exit_code!=0:raise unknown('child_exit')
   stage='post_identity'
   try:self._identity()
   except TransportRefused:raise unknown('post_identity') from None
   return bytes(out)
  except TransportRefused:raise
  except Exception:raise unknown(stage) from None
  finally:
   if selector:selector.close()
   if process and process.stdin and not process.stdin.closed:process.stdin.close()
   if process and process.poll() is None:
    process.kill();process.wait(timeout=5)
