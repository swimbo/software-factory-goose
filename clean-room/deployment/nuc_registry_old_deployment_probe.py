#!/usr/bin/python3
"""Fixed UID2004 read-only metadata for the retired SDK4 URI."""
import ctypes,errno,http.client,json,os,pathlib,re,socket,stat,sys
PATH='/var/lib/software-factory-goose/journal/restate/sfgoose-private/admin.sock';URI='http://127.0.0.1:9084'
class Conn(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(8);self.sock.connect(PATH)
def require(v,m):
 if not v:raise RuntimeError(m)
def parse(raw):
 def pairs(items):
  out={}
  for k,v in items:require(k not in out,'duplicate field');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('nonfinite')))
def get(path):
 c=Conn('localhost',timeout=8)
 try:c.request('GET',path,headers={'Accept':'application/json','Connection':'close'});r=c.getresponse();body=r.read(65537);require(r.status==200 and len(body)<=65536,'metadata unavailable');return parse(body)
 finally:c.close()
def main():
 require(len(sys.argv)==1 and (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2004,)*4,'identity');require(ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0,'dumpable')
 fields=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x);require(fields.get('NoNewPrivs','').strip()=='1' and all(int(fields.get('Cap'+k,'1').strip(),16)==0 for k in ('Inh','Prm','Eff','Bnd','Amb')),'privileges')
 raw=sys.stdin.buffer.read(1025);require(len(raw)<=1024,'request oversized');request=parse(raw);require(set(request)=={'namespace_dev','namespace_ino','socket_dev','socket_ino'} and all(type(v) is int and v>0 for v in request.values()),'namespace request');ns=os.stat('/proc/self/ns/net');require((ns.st_dev,ns.st_ino)==(request['namespace_dev'],request['namespace_ino']),'namespace changed')
 st=os.lstat(PATH);require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(2004,2004,1,0o700) and (st.st_dev,st.st_ino)==(request['socket_dev'],request['socket_ino']),'admin socket changed')
 try:os.getxattr(PATH,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'socket ACL unavailable')
 else:raise RuntimeError('socket ACL present')
 value=get('/deployments');require(isinstance(value,dict) and set(value)=={'deployments'} and isinstance(value['deployments'],list) and len(value['deployments'])<=256,'deployment inventory');matches=[x for x in value['deployments'] if isinstance(x,dict) and x.get('uri') in (URI,URI+'/')];require(len(matches)==1 and isinstance(matches[0].get('id'),str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',matches[0]['id']),'deployment identity');ident=matches[0]['id']
 detail=get('/deployments/'+ident);require(isinstance(detail,dict) and detail.get('id')==ident and detail.get('uri') in (URI,URI+'/') and isinstance(detail.get('services'),list),'deployment detail');require(len(detail['services'])==4 and all(isinstance(x,dict) for x in detail['services']),'service set');names=[x.get('name') for x in detail['services']];require(len(names)==4 and sorted(names)==sorted(['ClaimLeaseJournal','IntakeJournal','RuntimeIntakeJournal','WorkerQueueJournal']),'service set');last=os.lstat(PATH);require((last.st_dev,last.st_ino)==(st.st_dev,st.st_ino),'socket changed');print(json.dumps({'schema':1,'deployment_id':ident,'uri':URI,'service_count':4},sort_keys=True,separators=(',',':')))
if __name__=='__main__':
 try:main()
 except Exception:print('retired deployment metadata unavailable',file=sys.stderr);raise SystemExit(1)
