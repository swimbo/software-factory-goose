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
 require(len(sys.argv)==2 and sys.argv[1] in ('register-old','register-new'),'unsupported fixed operation')
 endpoint={'register-old':'http://127.0.0.1:9081','register-new':'http://127.0.0.1:9082'}[sys.argv[1]]
 c=Connection('localhost',timeout=8)
 try:
  c.request('POST','/deployments',json.dumps({'uri':endpoint,'force':False,'breaking':False},separators=(',',':')).encode(),{'Content-Type':'application/json','Accept':'application/json'})
  r=c.getresponse();body=r.read(65537);require(r.status==201 and len(body)<=65536,'registration unknown');data=json.loads(body);ident=data.get('id');services=data.get('services')
  require(isinstance(ident,str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',ident) and isinstance(services,list) and len(services)==1 and isinstance(services[0],dict) and services[0].get('name')=='FenceFixture','registration result invalid')
  c.close();c=Connection('localhost',timeout=8);c.request('GET','/deployments/'+ident,headers={'Accept':'application/json'});r=c.getresponse();body=r.read(65537);require(r.status==200 and len(body)<=65536,'metadata unavailable');meta=json.loads(body)
  require(isinstance(meta,dict) and meta.get('id')==ident and meta.get('uri','').rstrip('/')==endpoint and isinstance(meta.get('services'),list) and len(meta['services'])==1 and isinstance(meta['services'][0],dict) and meta['services'][0].get('name')=='FenceFixture','deployment metadata mismatch')
  print(json.dumps({'schema':1,'operation':sys.argv[1],'deployment_id':ident,'service_name':'FenceFixture','uri':endpoint},sort_keys=True,separators=(',',':')))
 finally:c.close()
if __name__=='__main__':main()
