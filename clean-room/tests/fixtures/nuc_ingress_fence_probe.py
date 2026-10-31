#!/usr/bin/python3
"""Fixed UID2000 synthetic ingress/discovery probe, owned fixture only."""
import http.client,json,os,pathlib,socket,stat,sys,time
MARKER=pathlib.Path('/var/lib/software-factory-goose/unix-admin-canary/handshake/old.stopped')
MAX=16384

def require(v,m):
 if not v:raise RuntimeError(m)
def identity():
 require((os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2000,2000,2000,2000),'identity unavailable')
 f=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
 require(f.get('NoNewPrivs','').strip()=='1' and all(int(f[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')),'privileges unavailable')
def response(c,method,path,headers=None):
 c.request(method,path,headers=headers or {});r=c.getresponse();data=r.read(MAX+1);require(len(data)<=MAX,'response oversized');return r.status,data
def post(c,path):
 status,body=response(c,'POST',path,{'Content-Length':'0'});require(200<=status<300,'ingress outcome unknown');return body
def send(c,path):
 c.request('POST',path,headers={'Content-Length':'0'});r=c.getresponse();data=r.read(MAX+1)
 require(r.status==202 and len(data)<=MAX,'send outcome unknown')
 obj=json.loads(data);identity=r.getheader('x-restate-id')
 require(isinstance(obj,dict) and isinstance(identity,str) and 1<=len(identity)<=256 and identity.isascii() and identity.isprintable() and obj.get('invocationId')==identity and obj.get('status')=='Accepted','send receipt unavailable')
 return identity
def verify_reuse(direct,held_socket,ingress,ingress_socket):
 require(direct.sock is held_socket,'original discovery connection unavailable')
 status,body=response(direct,'GET','/discover',{'Accept':'application/vnd.restate.endpointmanifest.v4+json'});manifest=json.loads(body)
 require(status==200 and any(x.get('name')=='FenceFixture' for x in manifest.get('services',[])) and direct.sock is held_socket,'original discovery reuse unavailable')
 require(ingress.sock is ingress_socket,'original ingress connection unavailable')
 value=json.loads(post(ingress,'/restate/call/FenceFixture/history/inspect'))
 require(value=={'version':'old','count':1} and ingress.sock is ingress_socket,'original ingress reuse unavailable')
def marker():
 try:fd=os.open(MARKER,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 except FileNotFoundError:return False
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2000,1,0o440) and st.st_size<=1024,'marker unavailable')
  try:os.getxattr(fd,'system.posix_acl_access')
  except OSError as e:require(e.errno==__import__('errno').ENODATA,'marker ACL unavailable')
  else:raise RuntimeError('marker ACL present')
  return os.read(fd,1025)==b'stopped\n'
 finally:os.close(fd)
def main():
 require(len(sys.argv)==1,'arguments forbidden');identity()
 direct=http.client.HTTPConnection('127.0.0.1',9081,timeout=5);ingress=http.client.HTTPConnection('127.0.0.1',8080,timeout=5)
 try:
  status,body=response(direct,'GET','/discover',{'Accept':'application/vnd.restate.endpointmanifest.v4+json'});manifest=json.loads(body);require(status==200 and any(x.get('name')=='FenceFixture' for x in manifest.get('services',[])) and direct.sock is not None,'direct discovery unavailable')
  held_socket=direct.sock
  value=json.loads(post(ingress,'/restate/call/FenceFixture/history/increment'));require(value=={'version':'old','count':1},'positive mutation unavailable')
  require(json.loads(post(ingress,'/restate/call/FenceFixture/scheduler/schedule')) is True,'schedule unavailable')
  hold=send(ingress,'/restate/send/FenceFixture/blocked/hold');queued=send(ingress,'/restate/send/FenceFixture/blocked/increment')
  require(hold!=queued and ingress.sock is not None,'invocation identity or ingress connection unavailable')
  ingress_socket=ingress.sock
  verify_reuse(direct,held_socket,ingress,ingress_socket)
  print(json.dumps({'stage':'before_retirement','positive_old_count':1,'direct_discovery':True,'direct_reused':True,'ingress_reused':True,'hold':hold,'queued':queued},sort_keys=True),flush=True)
  end=time.monotonic()+900
  while not marker():
   require(time.monotonic()<end,'retirement not observed');time.sleep(.1)
  # An existing discovery connection must not still reach the old process.
  try:
   held_socket.settimeout(2);held_socket.sendall(b'GET /discover HTTP/1.1\r\nHost: localhost\r\nAccept: application/vnd.restate.endpointmanifest.v4+json\r\nConnection: close\r\n\r\n')
   reply=held_socket.recv(4096);require(not reply,'retired endpoint still responds')
  except TimeoutError:raise RuntimeError('existing connection outcome unknown') from None
  except (ConnectionError,OSError,http.client.HTTPException):pass
  try:
   with socket.create_connection(('127.0.0.1',9081),timeout=2):raise RuntimeError('retired listener still accepts')
  except ConnectionRefusedError:pass
  except TimeoutError:raise RuntimeError('new connection outcome unknown') from None
  require(ingress.sock is ingress_socket,'original ingress connection unavailable')
  after=send(ingress,'/restate/send/FenceFixture/after/increment');require(after not in (hold,queued) and ingress.sock is ingress_socket,'invocation identity or ingress connection changed')
  print(json.dumps({'stage':'after_retirement','old_connection_denied':True,'new_connection_denied':True,'forwarded':after,'effect':'requires journal inspection'},sort_keys=True),flush=True)
 finally:direct.close();ingress.close()
if __name__=='__main__':main()
