#!/usr/bin/python3
"""Same-UID socket-FD observation; caller authenticates PID1 unit identity.

 No FD path, inode, payload, command, credential or environment is emitted.
 This tests visibility only and makes no claim about inherited admin sockets.
"""
import ctypes,json,os,pathlib,re,sys
ADMIN='/var/lib/software-factory-goose/journal/restate/sfgoose-private/admin.sock'
def require(v,m):
 if not v:raise RuntimeError(m)
def pairs(items):
 out={}
 for k,v in items:require(k not in out,'duplicate field');out[k]=v
 return out
def ticks(pid):
 raw=pathlib.Path('/proc',str(pid),'stat').read_text();require(len(raw)<8192 and ')' in raw,'process unavailable');return int(raw.rsplit(')',1)[1].split()[19])
def main():
 require(len(sys.argv)==2 and sys.argv[1]=='facility' and (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2000,)*4,'identity unavailable')
 fields=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
 require(fields.get('NoNewPrivs','').strip()=='1' and all(fields.get('Cap'+n,'').strip()=='0000000000000000' for n in ('Inh','Prm','Eff','Bnd','Amb')),'privileges unavailable')
 require(ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0,'dumpable change unavailable')
 raw=sys.stdin.buffer.read(2049);require(len(raw)<=2048,'request oversized');req=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('nonfinite')))
 require(isinstance(req,dict) and set(req)=={'pid','start_ticks','namespace_dev','namespace_ino'} and all(type(req[k]) is int and req[k]>0 for k in req),'request unavailable');pid=req['pid'];require(pid>1,'PID unavailable')
 ns=os.stat('/proc/self/ns/net');require((ns.st_dev,ns.st_ino)==(req['namespace_dev'],req['namespace_ino']),'namespace changed')
 status=pathlib.Path('/proc',str(pid),'status').read_text();require(len(status)<=65536,'status oversized');proc=dict(x.split(':',1) for x in status.splitlines() if ':' in x);require(proc.get('Uid','').split()==['2000']*4 and proc.get('Gid','').split()==['2000']*4 and ticks(pid)==req['start_ticks'],'target identity changed')
 fdroot=pathlib.Path('/proc',str(pid),'fd');names=os.listdir(fdroot);require(len(names)<=1024 and all(re.fullmatch(r'[0-9]+',n) for n in names),'FD inventory unavailable')
 socket_count=0
 for name in names:
  link=os.readlink(fdroot/name)
  if re.fullmatch(r'socket:\[([0-9]+)\]',link):socket_count+=1
 require(ticks(pid)==req['start_ticks'],'target identity changed')
 print(json.dumps({'schema':1,'mode':'facility','fd_count':len(names),'socket_fd_count':socket_count},sort_keys=True,separators=(',',':')))

if __name__=='__main__':
 try:main()
 except Exception:print('FD observation unavailable',file=sys.stderr);raise SystemExit(1)
