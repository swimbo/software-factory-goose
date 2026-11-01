#!/usr/bin/python3
"""Fixed UID2004 private-admin observation, not an admission authority.

 Only counts and socket identity are returned. Caller must independently bind
 PID1 namespace, the protected SDK5 deployment and all retirement fences.
"""
import ctypes,errno,http.client,json,os,pathlib,re,socket,stat,sys
ADMIN='/var/lib/software-factory-goose/journal/restate/sfgoose-private/admin.sock'
class Conn(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(8);self.sock.connect(ADMIN)
def require(v,m):
 if not v:raise RuntimeError(m)
def unique(pairs):
 result={}
 for k,v in pairs:require(k not in result,'duplicate JSON');result[k]=v
 return result
def parse(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('invalid number')))
def validated_id(value):
 require(isinstance(value,str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',value),'deployment ID unavailable');return value
def main():
 require(len(sys.argv)==1 and (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2004,)*4,'identity unavailable')
 status=dict(x.split(':',1) for x in open('/proc/self/status') if ':' in x);require(status.get('NoNewPrivs','').strip()=='1' and all(status.get('Cap'+n,'').strip()=='0000000000000000' for n in ('Inh','Prm','Eff','Bnd','Amb')),'privileges unavailable')
 require(ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0,'dumpable change unavailable')
 raw=sys.stdin.buffer.read(4097);require(len(raw)<=4096,'request oversized');request=parse(raw)
 require(isinstance(request,dict) and set(request)=={'schema','sdk5_deployment_id','namespace_dev','namespace_ino'} and type(request['schema']) is int and request['schema']==1 and all(type(request[k]) is int and request[k]>0 for k in ('namespace_dev','namespace_ino')),'request unavailable')
 sdk5=validated_id(request['sdk5_deployment_id'])
 ns=os.stat('/proc/self/ns/net');require((ns.st_dev,ns.st_ino)==(request['namespace_dev'],request['namespace_ino']),'namespace unavailable')
 for port in (9081,9082,9083,9084,9070):
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:s.settimeout(2);require(s.connect_ex(('127.0.0.1',port))==errno.ECONNREFUSED,'old or TCP admin listener present')
 for path in ('/proc/self/net/tcp','/proc/self/net/tcp6'):
  for line in pathlib.Path(path).read_text().splitlines()[1:]:
   fields=line.split();require(len(fields)>=4,'socket table unavailable');port=int(fields[1].rsplit(':',1)[1],16)
   require(not(port in (9081,9082,9083,9084,9070) and fields[3] in ('01','0A')),'old or TCP admin socket present')
 st=os.lstat(ADMIN);require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(2004,2004,1,0o700),'admin socket unavailable')
 try:os.getxattr(ADMIN,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'admin ACL unavailable')
 else:raise RuntimeError('admin ACL present')
 sqlid="'"+sdk5+"'";services="'ClaimLeaseJournal','RuntimeIntakeJournal','WorkerQueueJournal','IntakeJournal'"
 queries={'invocations':f"SELECT COUNT(*) AS n FROM sys_invocation_status WHERE target_service_name IN ({services}) AND (status IS NULL OR status <> 'completed') AND (pinned_deployment_id IS NULL OR pinned_deployment_id <> {sqlid})",'queue_entries':f"SELECT COUNT(*) AS n FROM sys_vqueue_entry_status WHERE deployment IS NULL OR deployment <> {sqlid}",'queues':f"SELECT COUNT(*) AS n FROM sys_vqueues WHERE deployment IS NULL OR deployment <> {sqlid}"}
 counts={}
 for name,query in queries.items():
  c=Conn('localhost',timeout=8)
  try:
   c.request('POST','/query',json.dumps({'query':query},separators=(',',':')).encode(),{'Content-Type':'application/json','Accept':'application/json'});response=c.getresponse();data=response.read(4097);require(response.status==200 and len(data)<=4096,'admin query unavailable');obj=parse(data)
  finally:c.close()
  require(isinstance(obj,dict) and set(obj)=={'rows'} and isinstance(obj['rows'],list) and len(obj['rows'])==1 and isinstance(obj['rows'][0],dict) and set(obj['rows'][0])=={'n'} and type(obj['rows'][0]['n']) is int and obj['rows'][0]['n']>=0,'count unavailable');counts[name]=obj['rows'][0]['n']
 require(os.lstat(ADMIN).st_ino==st.st_ino and os.lstat(ADMIN).st_dev==st.st_dev,'admin socket changed')
 print(json.dumps({'schema':1,'admin_dev':st.st_dev,'admin_ino':st.st_ino,'old_listeners_and_established_absent':True,'tcp_admin_absent':True,'counts':counts},sort_keys=True,separators=(',',':')))
if __name__=='__main__':
 try:main()
 except Exception:print('admission observation unavailable',file=sys.stderr);raise SystemExit(1)
