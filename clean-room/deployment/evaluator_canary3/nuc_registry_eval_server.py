"""Socket-activated root evaluator broker transport; bootstrap remains required."""
import base64,errno,json,os,socket,stat,struct,time
from nuc_registry_eval_broker import Unavailable
PATH='/run/software-factory-goose/evaluator3/broker.sock'
def validate_listener(fd,no_acl):
 if os.getuid()!=0 or os.geteuid()!=0 or os.environ.get('LISTEN_PID')!=str(os.getpid()) or os.environ.get('LISTEN_FDS')!='1' or os.environ.get('LISTEN_FDNAMES')!='evaluator':raise Unavailable('listener unavailable')
 parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for name in ('run','software-factory-goose','evaluator3'):
   child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);os.close(parent);parent=child;info=os.fstat(parent);no_acl(parent,True)
   if name!='evaluator3' and (info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022):raise Unavailable('listener unavailable')
  st=os.fstat(parent);no_acl(parent,True)
  if (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(0,2002,0o710):raise Unavailable('listener unavailable')
  entry=os.stat('broker.sock',dir_fd=parent,follow_symlinks=False)
  if not stat.S_ISSOCK(entry.st_mode) or (entry.st_uid,entry.st_gid,stat.S_IMODE(entry.st_mode),entry.st_nlink)!=(0,2002,0o660,1):raise Unavailable('listener unavailable')
  try:os.getxattr('/proc/self/fd/'+str(parent)+'/broker.sock','system.posix_acl_access',follow_symlinks=False)
  except OSError as e:
   if e.errno!=errno.ENODATA:raise Unavailable('listener unavailable') from None
  else:raise Unavailable('listener unavailable')
 finally:os.close(parent)
 sock=socket.fromfd(fd,socket.AF_UNIX,socket.SOCK_STREAM)
 try:
  if sock.getsockname()!=PATH or sock.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)!=1:raise Unavailable('listener unavailable')
 finally:sock.close()
def handle(conn,broker):
 try:
  _,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
  if uid!=2002:raise Unavailable('peer unavailable')
  deadline=time.monotonic()+5;raw=bytearray()
  while b'\n' not in raw:
   remaining=deadline-time.monotonic()
   if remaining<=0:raise Unavailable('request unavailable')
   conn.settimeout(remaining)
   b=conn.recv(min(4097-len(raw),4096))
   if not b:raise Unavailable('request unavailable')
   raw.extend(b)
   if len(raw)>4096:raise Unavailable('request unavailable')
  if not raw.endswith(b'\n') or raw.count(b'\n')!=1:raise Unavailable('request unavailable')
  def unique(pairs):
   out={}
   for k,v in pairs:
    if k in out:raise ValueError('duplicate')
    out[k]=v
   return out
  q=json.loads(raw,object_pairs_hook=unique);r=broker.run(uid,q)
  for k in ('stdout','stderr'):r[k]=base64.b64encode(r[k]).decode('ascii')
  data=json.dumps(r,sort_keys=True,separators=(',',':')).encode()+b'\n'
  if len(data)>180000:raise Unavailable('response unavailable')
  conn.sendall(data)
 except Exception:
  try:conn.sendall(b'{"error":"unavailable"}\n')
  except OSError:pass
