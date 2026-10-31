#!/usr/bin/python3
"""Fixed UID2004 fixture admin operation. Root supervisor owns one-shot fencing."""
import http.client,json,os,re,socket,sys
SOCKET='/var/lib/software-factory-goose/unix-admin-canary/data/sfactory-unix-admin/admin.sock'
class Connection(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(8);self.sock.connect(SOCKET)
def require(v,msg):
 if not v:raise RuntimeError(msg)
def main():
 require((os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2004,2004,2004,2004),'identity')
 st=open('/proc/self/status').read();require('NoNewPrivs:\t1' in st and all(('Cap'+x+':\t0000000000000000') in st for x in ('Inh','Prm','Eff','Bnd','Amb')),'capabilities')
 require(len(sys.argv)==2 and sys.argv[1] in ('snapshot','old-uri-matches','new-uri-matches'),'unsupported fixed operation')
 if sys.argv[1] in ('old-uri-matches','new-uri-matches'):
  endpoint={'old-uri-matches':'http://127.0.0.1:9081','new-uri-matches':'http://127.0.0.1:9082'}[sys.argv[1]]
  c=Connection('localhost',timeout=8)
  try:
   c.request('GET','/deployments',headers={'Accept':'application/json'});r=c.getresponse();body=r.read(65537);require(r.status==200 and len(body)<=65536,'deployment list unknown');data=json.loads(body)
   require(isinstance(data,dict) and set(data)=={'deployments'} and isinstance(data['deployments'],list) and len(data['deployments'])<=64,'deployment list invalid');matches=[]
   for entry in data['deployments']:
    require(isinstance(entry,dict) and isinstance(entry.get('id'),str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',entry['id']) and isinstance(entry.get('uri'),str),'deployment entry invalid')
    if entry['uri'].rstrip('/')==endpoint:matches.append(entry['id'])
   require(len(matches)<=1,'deployment identity ambiguous')
   if matches:
    c.close();c=Connection('localhost',timeout=8);c.request('GET','/deployments/'+matches[0],headers={'Accept':'application/json'});r=c.getresponse();body=r.read(65537);require(r.status==200 and len(body)<=65536,'metadata unavailable');meta=json.loads(body)
    require(isinstance(meta,dict) and meta.get('id')==matches[0] and isinstance(meta.get('uri'),str) and meta['uri'].rstrip('/')==endpoint and isinstance(meta.get('services'),list) and len(meta['services'])==1 and isinstance(meta['services'][0],dict) and meta['services'][0].get('name')=='FenceFixture','metadata mismatch')
   print(json.dumps({'schema':1,'operation':sys.argv[1],'ids':matches},sort_keys=True,separators=(',',':')));return
  finally:c.close()
 if sys.argv[1]=='snapshot':
  queries={'invocations':"SELECT id,status,pinned_deployment_id,target_service_name,target_handler_name,target_service_key,scheduled_start_at,completion_result FROM sys_invocation_status WHERE target_service_name = 'FenceFixture' ORDER BY id LIMIT 101",'queue':"SELECT entry_id,deployment,status,stage,entry_kind FROM sys_vqueue_entry_status ORDER BY entry_id LIMIT 101",'state':"SELECT service_key,key,value_utf8 FROM state WHERE service_name = 'FenceFixture' AND key = 'count' ORDER BY service_key LIMIT 101"}
  rows={}
  for name,q in queries.items():
   c=Connection('localhost',timeout=8)
   try:
    c.request('POST','/query',json.dumps({'query':q},separators=(',',':')).encode(),{'Content-Type':'application/json','Accept':'application/json'});r=c.getresponse();body=r.read(65537);require(r.status==200 and len(body)<=65536,'snapshot unknown');item=json.loads(body);require(isinstance(item,dict) and set(item)=={'rows'} and isinstance(item['rows'],list) and len(item['rows'])<=100,'snapshot invalid');rows[name]=item['rows']
   finally:c.close()
  print(json.dumps({'schema':1,'operation':'snapshot','rows':rows},sort_keys=True,separators=(',',':')));return
if __name__=='__main__':main()
