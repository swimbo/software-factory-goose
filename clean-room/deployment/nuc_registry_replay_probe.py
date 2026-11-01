#!/usr/bin/python3
"""Read-only private Restate history hashing probe; no registration or mutation.

A root-controlled PID1 unit supplies a bounded target list on stdin. Output has
only target identifiers, state keys, content digests and counts; raw state,
lease capabilities and task contents are never printed or written.
"""
import ctypes,errno,hashlib,http.client,json,os,pathlib,re,stat,sys
from urllib.parse import urlsplit
ID=re.compile(r'[0-7][0-9A-HJKMNP-TV-Z]{25}\Z');KEY=re.compile(r'[A-Za-z0-9_-]{1,256}\Z')
SERVICES={'ClaimLeaseJournal','RuntimeIntakeJournal','WorkerQueueJournal'}
ALLOWED_KEYS={'claim','launch_reservation_v1','claim_event_history_v1','projection_quarantine','root_finalization_v1','handoff','published','queue'}
MAX_IN=32768;MAX_OUT=1048576;ADMIN_PORT=9070
CONFIG=pathlib.Path('/etc/software-factory-goose/runtime.json');CONFIG_SHA='53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6'

def require(v,msg):
 if not v:raise RuntimeError(msg)
def unique(pairs):
 d={}
 for k,v in pairs:
  require(k not in d,'duplicate JSON field');d[k]=v
 return d
def parse(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('nonfinite JSON')))
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def targets(data):
 require(isinstance(data,dict) and set(data)=={'schema','targets','deployment_id','sdk_uri'} and type(data['schema']) is int and data['schema']==1 and isinstance(data['targets'],list) and 1<=len(data['targets'])<=48,'target scope unavailable')
 require(isinstance(data['deployment_id'],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',data['deployment_id']),'deployment identity unavailable')
 u=urlsplit(data['sdk_uri']);require(u.scheme=='http' and u.hostname=='127.0.0.1' and u.port in (9084,9085) and u.path in ('','/') and not u.query and not u.fragment and u.username is None and u.password is None,'SDK URI unavailable')
 out=[]
 for t in data['targets']:
  require(isinstance(t,dict) and set(t)=={'service','key'} and t['service'] in SERVICES and isinstance(t['key'],str) and KEY.fullmatch(t['key']),'target unavailable')
  if t['service']!='WorkerQueueJournal':require(ID.fullmatch(t['key']) is not None,'target ID unavailable')
  pair=(t['service'],t['key']);require(pair not in out,'duplicate target');out.append(pair)
 return sorted(out)
def query(service,key):
 # Values interpolate only allowlisted service names and ASCII identifiers with no SQL metacharacters.
 text="SELECT key, value_utf8 FROM state WHERE service_name = '"+service+"' AND service_key = '"+key+"' ORDER BY key"
 c=http.client.HTTPConnection('127.0.0.1',ADMIN_PORT,timeout=8)
 try:
  c.request('POST','/query',canonical({'query':text}),{'Content-Type':'application/json','Accept':'application/json','Connection':'close'});r=c.getresponse();raw=r.read(MAX_OUT+1)
  require(r.status==200 and len(raw)<=MAX_OUT,'history query unavailable')
 finally:c.close()
 # The pinned server's query content type and row schema must be confirmed by
 # the disposable fixture; unknown formats fail closed, not an empty history.
 envelope=parse(raw);require(isinstance(envelope,dict) and set(envelope)=={'rows'} and isinstance(envelope['rows'],list) and len(envelope['rows'])<=128,'history rows unavailable');rows=envelope['rows'];out=[];seen=set()
 for row in rows:
  require(isinstance(row,dict) and set(row)=={'key','value_utf8'} and isinstance(row['key'],str) and row['key'] in ALLOWED_KEYS and row['key'] not in seen and isinstance(row['value_utf8'],str),'history row invalid')
  seen.add(row['key']);out.append({'key':row['key'],'value_sha256':hashlib.sha256(row['value_utf8'].encode()).hexdigest()})
 return out
def deployment(identity,uri):
 c=http.client.HTTPConnection('127.0.0.1',ADMIN_PORT,timeout=8)
 try:
  c.request('GET','/deployments/'+identity,headers={'Accept':'application/json','Connection':'close'});r=c.getresponse();raw=r.read(65537)
  require(r.status==200 and len(raw)<=65536,'deployment unavailable')
 finally:c.close()
 obj=parse(raw);require(isinstance(obj,dict) and obj.get('id')==identity and isinstance(obj.get('uri'),str),'deployment metadata mismatch')
 actual=urlsplit(obj['uri']);expected=urlsplit(uri)
 require(actual.scheme==expected.scheme and actual.hostname==expected.hostname and actual.port==expected.port and actual.path in ('','/') and not actual.query and not actual.fragment and actual.username is None and actual.password is None,'deployment metadata mismatch')
 return hashlib.sha256(raw).hexdigest()
def main():
 require(ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0,'dump protection unavailable')
 require(os.getuid()==2000 and os.geteuid()==2000 and os.getgid()==2000 and os.getegid()==2000 and len(sys.argv)==1,'fixed control identity required')
 fields=dict(line.split(':',1) for line in open('/proc/self/status',encoding='ascii') if ':' in line)
 require(all(int(fields[k].strip(),16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) and fields['NoNewPrivs'].strip()=='1','capability profile unavailable')
 fd=os.open(CONFIG,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o644 and 0<st.st_size<=65536,'namespace config unavailable')
  try:os.getxattr(fd,'system.posix_acl_access');raise RuntimeError('config ACL present')
  except OSError as e:require(e.errno==errno.ENODATA,'config ACL unavailable')
  config=os.read(fd,65537);require(len(config)==st.st_size and hashlib.sha256(config).hexdigest()==CONFIG_SHA,'namespace config changed')
 finally:os.close(fd)
 cfg=parse(config);ns=os.stat('/proc/self/ns/net');require((ns.st_dev,ns.st_ino)==(cfg['namespace_dev'],cfg['namespace_ino']) and (ns.st_dev,ns.st_ino)!=(cfg['host_namespace_dev'],cfg['host_namespace_ino']),'private namespace unavailable')
 raw=sys.stdin.buffer.read(MAX_IN+1);require(len(raw)<=MAX_IN,'input oversized');data=parse(raw);items=targets(data)
 metadata=deployment(data['deployment_id'],data['sdk_uri']);results=[{'service':service,'key':key,'rows':query(service,key)} for service,key in items]
 print(json.dumps({'schema':1,'deployment_id':data['deployment_id'],'deployment_metadata_sha256':metadata,'histories':results},sort_keys=True,separators=(',',':')))
if __name__=='__main__':
 try:main()
 except Exception:
  print('registry replay probe unavailable',file=sys.stderr);raise SystemExit(1)
