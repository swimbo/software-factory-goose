#!/usr/bin/python3
"""Fixed PID1 role probe for the provisioned production Unix admin endpoint."""
import ctypes,errno,http.client,json,os,pathlib,socket,stat,sys
PATH='/var/lib/software-factory-goose/journal/restate/sfgoose-private/admin.sock'
def require(v,m):
 if not v:raise RuntimeError(m)
class Conn(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5);self.sock.connect(PATH)
def main():
 require(len(sys.argv)==2 and sys.argv[1] in ('journal','control'),'role unavailable');role=sys.argv[1];uid=2004 if role=='journal' else 2000
 require((os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(uid,)*4,'identity unavailable')
 st=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x);require(st.get('NoNewPrivs','').strip()=='1' and all(int(st.get('Cap'+x,'1').strip(),16)==0 for x in ('Inh','Prm','Eff','Bnd','Amb')),'privileges unavailable');require(ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0,'dump protection unavailable')
 raw=sys.stdin.buffer.read(1025);require(len(raw)<=1024,'request too large');r=json.loads(raw);require(isinstance(r,dict) and set(r)=={'namespace_dev','namespace_ino'} and all(type(r[k]) is int and r[k]>0 for k in r),'request unavailable');ns=os.stat('/proc/self/ns/net');require((ns.st_dev,ns.st_ino)==(r['namespace_dev'],r['namespace_ino']),'namespace changed')
 with socket.socket() as s:s.settimeout(2);require(s.connect_ex(('127.0.0.1',9070))==errno.ECONNREFUSED,'TCP admin listener present')
 for path in ('/proc/self/net/tcp','/proc/self/net/tcp6'):
  for line in pathlib.Path(path).read_text().splitlines()[1:]:
   fields=line.split();require(len(fields)>=4,'socket table unavailable');require(not(int(fields[1].rsplit(':',1)[1],16)==9070 and fields[3] in ('01','0A')),'TCP admin socket present')
 if role=='control':
  try:
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:s.settimeout(2);s.connect(PATH)
  except OSError as e:require(e.errno in (errno.EACCES,errno.EPERM),'admin denial unknown')
  else:raise RuntimeError('control reached admin')
  print(json.dumps({'schema':1,'admin_denied':True,'tcp_admin_absent':True},sort_keys=True));return
 st=os.lstat(PATH);require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(2004,2004,1,0o700),'socket unavailable')
 try:os.getxattr(PATH,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'socket ACL unavailable')
 else:raise RuntimeError('socket ACL present')
 c=Conn('localhost',timeout=5)
 try:c.request('GET','/deployments',headers={'Accept':'application/json'});response=c.getresponse();body=response.read(65537);require(response.status==200 and len(body)<=65536 and isinstance(json.loads(body).get('deployments'),list),'admin unavailable')
 finally:c.close()
 again=os.lstat(PATH);require((again.st_dev,again.st_ino)==(st.st_dev,st.st_ino),'socket changed')
 print(json.dumps({'schema':1,'admin_ok':True,'tcp_admin_absent':True,'socket_dev':st.st_dev,'socket_ino':st.st_ino},sort_keys=True))
if __name__=='__main__':
 try:main()
 except Exception:print('Unix admin role probe unavailable',file=sys.stderr);raise SystemExit(1)
