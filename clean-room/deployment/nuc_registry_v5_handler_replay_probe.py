#!/usr/bin/python3
"""Fixed non-dumpable SDK5 historical handler replay; raw state stays in memory."""
import ctypes,errno,hashlib,http.client,json,os,pathlib,re,socket,stat,sys
ADMIN='/var/lib/software-factory-goose/journal/restate/sfgoose-private/admin.sock';SERVICES={'IntakeJournal','RuntimeIntakeJournal','ClaimLeaseJournal','WorkerQueueJournal'}
ID=re.compile(r'[0-7][0-9A-HJKMNP-TV-Z]{25}\Z');KEY=re.compile(r'[A-Za-z0-9_-]{1,256}\Z')
def require(v,m):
 if not v:raise RuntimeError(m)
def unique(items):
 out={}
 for k,v in items:require(k not in out,'duplicate JSON');out[k]=v
 return out
def parse(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('nonfinite')))
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
class Conn(http.client.HTTPConnection):
 def connect(self):self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(8);self.sock.connect(ADMIN)
def query(sql):
 c=Conn('localhost',timeout=8)
 try:c.request('POST','/query',canonical({'query':sql}),{'Content-Type':'application/json','Accept':'application/json','Connection':'close'});r=c.getresponse();body=r.read(1048577);require(r.status==200 and len(body)<=1048576,'query unavailable');out=parse(body)
 finally:c.close()
 require(isinstance(out,dict) and set(out)=={'rows'} and isinstance(out['rows'],list) and len(out['rows'])<=128,'rows unavailable');return out['rows']
def call(service,key,handler,body,deployment):
 c=http.client.HTTPConnection('127.0.0.1',8080,timeout=8)
 try:
  c.request('POST','/restate/call/'+service+'/'+key+'/'+handler,body,{'Content-Type':'application/json','Connection':'close'});r=c.getresponse();raw=r.read(1048577);inv=r.getheader('x-restate-id');require(r.status==200 and len(raw)<=1048576 and isinstance(inv,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,256}',inv),'handler unavailable');result=parse(raw)
 finally:c.close()
 rows=query("SELECT pinned_deployment_id FROM sys_invocation_status WHERE id = '"+inv+"' LIMIT 2");require(len(rows)==1 and rows[0]=={'pinned_deployment_id':deployment},'handler deployment mismatch')
 return result
def main():
 require(len(sys.argv)==1 and (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2004,)*4,'identity');require(ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0,'dumpable')
 fields=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x);require(fields.get('NoNewPrivs','').strip()=='1' and all(int(fields.get('Cap'+k,'1').strip(),16)==0 for k in ('Inh','Prm','Eff','Bnd','Amb')),'privileges')
 raw=sys.stdin.buffer.read(32769);require(len(raw)<=32768,'request too large');request=parse(raw);require(isinstance(request,dict) and set(request)=={'schema','namespace_dev','namespace_ino','socket_dev','socket_ino','deployment_id','targets'} and type(request['schema']) is int and request['schema']==1,'request')
 ns=os.stat('/proc/self/ns/net');require((ns.st_dev,ns.st_ino)==(request['namespace_dev'],request['namespace_ino']),'namespace');st=os.lstat(ADMIN);require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(2004,2004,1,0o700) and (st.st_dev,st.st_ino)==(request['socket_dev'],request['socket_ino']),'admin socket')
 try:os.getxattr(ADMIN,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'socket ACL unavailable')
 else:raise RuntimeError('socket ACL present')
 deployment=request['deployment_id'];require(isinstance(deployment,str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',deployment),'deployment')
 targets=request['targets'];require(isinstance(targets,list) and 1<=len(targets)<=64,'target count');pairs=[]
 for t in targets:
  require(isinstance(t,dict) and set(t)=={'service','key'} and t['service'] in SERVICES and isinstance(t['key'],str) and KEY.fullmatch(t['key']) and (t['service']=='WorkerQueueJournal' or ID.fullmatch(t['key'])),'target');pairs.append((t['service'],t['key']))
 require(pairs==sorted(set(pairs)),'target order');results=[];count=0
 for service,key in pairs:
  rows=query("SELECT key, value_utf8 FROM state WHERE service_name = '"+service+"' AND service_key = '"+key+"' ORDER BY key LIMIT 129");state={}
  for row in rows:
   require(isinstance(row,dict) and set(row)=={'key','value_utf8'} and isinstance(row['key'],str) and row['key'] not in state and isinstance(row['value_utf8'],str),'state');state[row['key']]=parse(row['value_utf8'])
  cases=[]
  if service=='IntakeJournal':cases=[('inspect',b'',state.get('intake'))]
  elif service=='ClaimLeaseJournal':cases=[('status',b'',state.get('claim'))]
  elif service=='RuntimeIntakeJournal':cases=[('inspect',b'',state.get('handoff') if state.get('published') is True else None)]
  else:
   queue=state.get('queue');pulls=[] if queue is None else queue.get('pulls');require(isinstance(pulls,list) and len(pulls)<=32,'queue pulls')
   for item in pulls:
    require(isinstance(item,dict) and isinstance(item.get('request'),dict) and isinstance(item['request'].get('request_id'),str) and ID.fullmatch(item['request']['request_id']) and 'outcome' in item,'pull receipt');cases.append(('lookup_pull',canonical(item['request']['request_id']),item['outcome']))
   if not cases:cases=[('lookup_pull',canonical('00000000000000000000000000'),None)]
  for handler,body,expected in cases:
   count+=1;require(count<=256,'replay bound');actual=call(service,key,handler,body,deployment);require(canonical(actual)==canonical(expected),'historical handler mismatch');results.append({'service':service,'key':key,'handler':handler,'value_sha256':sha(canonical(actual))})
 end=os.lstat(ADMIN);require((end.st_dev,end.st_ino)==(st.st_dev,st.st_ino),'admin socket changed')
 print(json.dumps({'schema':1,'deployment_id':deployment,'replayed_calls':count,'results_sha256':sha(canonical(results)),'raw_values_exposed':False},sort_keys=True,separators=(',',':')))
if __name__=='__main__':
 try:main()
 except Exception:print('historical handler replay unavailable',file=sys.stderr);raise SystemExit(1)
