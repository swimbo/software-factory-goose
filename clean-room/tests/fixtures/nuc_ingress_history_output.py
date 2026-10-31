#!/usr/bin/python3
"""Read only one synthetic invocation output; ID is passed by trusted supervisor."""
import hashlib,http.client,json,os,pathlib,re,sys
def require(v,m):
 if not v:raise RuntimeError(m)
def main():
 require(len(sys.argv)==1 and (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2000,)*4,'identity')
 status=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
 require(status.get('NoNewPrivs','').strip()=='1' and all(int(status[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')),'privileges')
 data=sys.stdin.buffer.read(257);require(data.endswith(b'\n') and re.fullmatch(rb'[A-Za-z0-9_-]{1,256}\n',data),'invocation identity')
 invocation=data[:-1].decode('ascii');c=http.client.HTTPConnection('127.0.0.1',8080,timeout=8)
 try:
  c.request('GET','/restate/output/'+invocation,headers={'Accept':'application/json','Connection':'close'});r=c.getresponse();raw=r.read(1025);require(r.status==200 and len(raw)<=1024,'output unavailable')
  def pairs(items):
   result={}
   for k,v in items:require(k not in result,'duplicate field');result[k]=v
   return result
  value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('nonfinite')))
  require(value=={'version':'old','count':1} and type(value.get('count')) is int,'history output mismatch')
  print(json.dumps({'schema':1,'invocation_sha256':hashlib.sha256(invocation.encode()).hexdigest(),'output_sha256':hashlib.sha256(raw).hexdigest(),'expected_response':True,'read_only':True},sort_keys=True,separators=(',',':')),flush=True)
 finally:c.close()
if __name__=='__main__':
 try:main()
 except Exception:print('history output unavailable',file=sys.stderr);sys.exit(1)
