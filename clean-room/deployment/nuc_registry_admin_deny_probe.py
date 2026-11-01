#!/usr/bin/python3
"""Fixed UID2000 read-only private-admin denial observation."""
import ctypes,errno,json,os,socket,sys
ADMIN='/var/lib/software-factory-goose/journal/restate/sfgoose-private/admin.sock'
def require(v,m):
 if not v:raise RuntimeError(m)
def unique(pairs):
 out={}
 for k,v in pairs:require(k not in out,'duplicate request');out[k]=v
 return out
def main():
 require(len(sys.argv)==1 and (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2000,)*4,'identity unavailable')
 status=dict(x.split(':',1) for x in open('/proc/self/status') if ':' in x);require(status.get('NoNewPrivs','').strip()=='1' and all(status.get('Cap'+n,'').strip()=='0000000000000000' for n in ('Inh','Prm','Eff','Bnd','Amb')),'privilege unavailable')
 require(ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0,'dumpable change unavailable')
 data=sys.stdin.buffer.read(1025);require(len(data)<=1024,'request oversized');request=json.loads(data,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('invalid number')))
 require(isinstance(request,dict) and set(request)=={'namespace_dev','namespace_ino'} and all(type(request[k]) is int and request[k]>0 for k in request),'namespace request unavailable')
 ns=os.stat('/proc/self/ns/net');require((ns.st_dev,ns.st_ino)==(request['namespace_dev'],request['namespace_ino']),'namespace changed')
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(3)
 try:
  try:s.connect(ADMIN)
  except OSError as e:require(e.errno==errno.EACCES,'admin denial unknown')
  else:raise RuntimeError('admin accessible')
 finally:s.close()
 print(json.dumps({'schema':1,'admin_access_denied':True},sort_keys=True,separators=(',',':')))
if __name__=='__main__':
 try:main()
 except Exception:print('admin denial observation unavailable',file=sys.stderr);raise SystemExit(1)
