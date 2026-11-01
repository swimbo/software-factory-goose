#!/usr/bin/python3
"""Hash only fixed registry history targets from live or isolated admin.

 The root supervisor must supply targets derived from the protected registry and
 bind the namespace to its PID1-owned anchor. This helper grants no authority.
"""
import ctypes,hashlib,http.client,json,os,re,socket,sys
SERVICES=('ClaimLeaseJournal','IntakeJournal','RuntimeIntakeJournal','WorkerQueueJournal')
ID=re.compile(r'[A-Za-z0-9_-]{1,256}\Z')
ULID=re.compile(r'[0-7][0-9A-HJKMNP-TV-Z]{25}\Z')
SOCKET='/var/lib/software-factory-goose/registry-transition-restore-5DEX7YKFGSEJN362KKSRNWP262/data/sfgoose-private/admin.sock'
class UnixConnection(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(8);self.sock.connect(SOCKET)
def require(v,m):
 if not v:raise RuntimeError(m)
def unique(pairs):
 result={}
 for k,v in pairs:require(k not in result,'duplicate key');result[k]=v
 return result
def parse(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('invalid number')))
def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def targets(value):
 require(isinstance(value,list) and 1<=len(value)<=48,'target count unavailable');result=[]
 for x in value:
  require(isinstance(x,dict) and set(x)=={'service','key'} and x['service'] in SERVICES and isinstance(x['key'],str) and ID.fullmatch(x['key']) and (x['service']=='WorkerQueueJournal' or ULID.fullmatch(x['key'])),'target unavailable')
  item=(x['service'],x['key']);require(item not in result,'duplicate target');result.append(item)
 require(result==sorted(result),'targets not sorted');return result
def main():
 require(len(sys.argv)==2 and sys.argv[1] in ('before','restore'),'mode unavailable');mode=sys.argv[1];uid=2004
 require((os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(uid,)*4,'identity unavailable')
 status=dict(x.split(':',1) for x in open('/proc/self/status') if ':' in x);require(status.get('NoNewPrivs','').strip()=='1' and all(status.get('Cap'+n,'').strip()=='0000000000000000' for n in ('Inh','Prm','Eff','Bnd','Amb')),'privilege unavailable')
 require(ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0,'dumpable change unavailable')
 raw=sys.stdin.buffer.read(32769);require(len(raw)<=32768,'request bound exceeded');request=parse(raw)
 require(isinstance(request,dict) and set(request)=={'schema','targets','namespace_dev','namespace_ino'} and type(request['schema']) is int and request['schema']==1 and all(type(request[x]) is int and request[x]>0 for x in ('namespace_dev','namespace_ino')),'request unavailable')
 ns=os.stat('/proc/self/ns/net');require((ns.st_dev,ns.st_ino)==(request['namespace_dev'],request['namespace_ino']),'namespace changed')
 result=[]
 for service,key in targets(request['targets']):
  query="SELECT key, value_utf8 FROM state WHERE service_name = '"+service+"' AND service_key = '"+key+"' ORDER BY key LIMIT 129"
  c=http.client.HTTPConnection('127.0.0.1',9070,timeout=8) if mode=='before' else UnixConnection('localhost',timeout=8)
  try:
   c.request('POST','/query',canonical({'query':query}),{'Content-Type':'application/json','Accept':'application/json','Connection':'close'});response=c.getresponse();data=response.read(1048577);require(response.status==200 and len(data)<=1048576,'query unavailable')
  finally:c.close()
  obj=parse(data);require(isinstance(obj,dict) and set(obj)=={'rows'} and isinstance(obj['rows'],list) and len(obj['rows'])<=128,'query rows unavailable');rows=[];seen=set()
  for row in obj['rows']:
   require(isinstance(row,dict) and set(row)=={'key','value_utf8'} and isinstance(row['key'],str) and len(row['key'])<=256 and row['key'] not in seen and isinstance(row['value_utf8'],str),'row unavailable');seen.add(row['key']);rows.append({'key_sha256':hashlib.sha256(row['key'].encode()).hexdigest(),'value_sha256':hashlib.sha256(row['value_utf8'].encode()).hexdigest()})
  query="SELECT id,status,pinned_deployment_id,target_handler_name,scheduled_start_at,completion_result FROM sys_invocation_status WHERE target_service_name = '"+service+"' AND target_service_key = '"+key+"' ORDER BY id LIMIT 129"
  c=http.client.HTTPConnection('127.0.0.1',9070,timeout=8) if mode=='before' else UnixConnection('localhost',timeout=8)
  try:
   c.request('POST','/query',canonical({'query':query}),{'Content-Type':'application/json','Accept':'application/json','Connection':'close'});response=c.getresponse();data=response.read(1048577);require(response.status==200 and len(data)<=1048576,'invocation query unavailable')
  finally:c.close()
  obj=parse(data);require(isinstance(obj,dict) and set(obj)=={'rows'} and isinstance(obj['rows'],list) and len(obj['rows'])<=128,'invocation rows unavailable');invocations=[];seen_ids=set()
  for row in obj['rows']:
   require(isinstance(row,dict) and set(row)=={'id','status','pinned_deployment_id','target_handler_name','scheduled_start_at','completion_result'} and isinstance(row['id'],str) and row['id'] not in seen_ids,'invocation row unavailable');seen_ids.add(row['id']);invocations.append(hashlib.sha256(canonical(row)).hexdigest())
  result.append({'service':service,'key':key,'rows':rows,'invocations':invocations})
 print(json.dumps({'schema':1,'histories':result},sort_keys=True,separators=(',',':')))
if __name__=='__main__':
 try:main()
 except Exception:print('restore history observation unavailable',file=sys.stderr);raise SystemExit(1)
