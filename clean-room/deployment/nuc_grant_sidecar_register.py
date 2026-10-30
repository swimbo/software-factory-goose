#!/usr/bin/python3
"""Single non-force registration of one fixed, new private SDK URI."""
import http.client,json,os,re,socket,time
if os.geteuid()!=2000:raise RuntimeError('registration identity mismatch')
for port in (9082,9070):
 for _ in range(150):
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=.1):break
  except OSError:time.sleep(.1)
 else:raise RuntimeError('private service unavailable')
body=json.dumps({'uri':'http://127.0.0.1:9082','force':False},separators=(',',':')).encode()
c=http.client.HTTPConnection('127.0.0.1',9070,timeout=10)
try:
 c.request('POST','/deployments',body,{'Content-Type':'application/json'})
 r=c.getresponse();raw=r.read(65537)
 if r.status!=201 or len(raw)>65536:raise RuntimeError('registration rejected or unknown')
 data=json.loads(raw);ident=data.get('id');services=data.get('services')
 if not isinstance(ident,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',ident) or not isinstance(services,list) or len(services)!=4:raise RuntimeError('registration response invalid or unknown')
 print('GRANT_REGISTRATION '+json.dumps({'id':ident,'service_count':len(services)},sort_keys=True),flush=True)
finally:c.close()
