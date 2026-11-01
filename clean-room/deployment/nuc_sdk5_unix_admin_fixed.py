#!/usr/bin/python3
"""Candidate fixed UID2004 SDK5 admin operations; root supervisor owns one-shot fencing.

No caller controls path, endpoint, SQL, request body, or deployment identifier.
The supervisor must attest the namespace/socket and persist intent before dispatch.
"""
import errno,http.client,json,os,pathlib,re,socket,stat,sys

SOCKET='/var/lib/software-factory-goose/journal/restate/sfgoose-private/admin.sock'
URI='http://127.0.0.1:9085'
SERVICES=('ClaimLeaseJournal','IntakeJournal','RuntimeIntakeJournal','WorkerQueueJournal')
BODY=b'{"uri":"http://127.0.0.1:9085","force":false,"breaking":false}'
LIMIT=65536

def require(v,msg):
    if not v:raise RuntimeError(msg)
def identity():
    require((os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2004,2004,2004,2004),'journal identity required')
    f=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
    require(f.get('NoNewPrivs','').strip()=='1' and all(f.get('Cap'+k,'').strip()=='0000000000000000' for k in ('Inh','Prm','Eff','Bnd','Amb')),'capability state invalid')
def socket_identity():
    s=os.lstat(SOCKET)
    require(stat.S_ISSOCK(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(2004,2004,1,0o700),'admin socket invalid')
    try:os.getxattr(SOCKET,'system.posix_acl_access',follow_symlinks=False)
    except OSError as e:require(e.errno==errno.ENODATA,'admin socket ACL unavailable')
    else:raise RuntimeError('admin socket ACL forbidden')
    return (s.st_dev,s.st_ino)
def parse(raw):
    def pairs(items):
        out={}
        for k,v in items:require(k not in out,'duplicate response field');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('invalid JSON')))
class Connection(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(8);self.sock.connect(SOCKET)
def get(path):
    c=Connection('localhost',timeout=8)
    try:
        c.request('GET',path,headers={'Accept':'application/json'});r=c.getresponse();raw=r.read(LIMIT+1)
        require(r.status==200 and len(raw)<=LIMIT,'admin response unavailable');return parse(raw)
    finally:c.close()
def uri_matches(value):
    require(isinstance(value,str),'deployment URI invalid')
    if value.rstrip('/')==URI:
        require(value in (URI,URI+'/'),'deployment URI ambiguous')
        return True
    return False
def matches():
    data=get('/deployments');require(isinstance(data,dict) and set(data)=={'deployments'} and isinstance(data['deployments'],list) and len(data['deployments'])<=256,'deployment list invalid')
    ids=[]
    for entry in data['deployments']:
        require(isinstance(entry,dict) and isinstance(entry.get('id'),str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',entry['id']) is not None and isinstance(entry.get('uri'),str),'deployment entry invalid')
        if uri_matches(entry['uri']):ids.append(entry['id'])
    require(len(ids)<=1,'SDK5 deployment ambiguous')
    return ids
def prezero():
    require(matches()==[],'SDK5 URI already registered')
    return {'schema':1,'operation':'sdk5-prezero','matches':0}
def reconcile():
    ids=matches();require(len(ids)==1,'SDK5 outcome unknown');data=get('/deployments/'+ids[0])
    require(isinstance(data,dict) and data.get('id')==ids[0] and uri_matches(data.get('uri')) and isinstance(data.get('services'),list),'SDK5 metadata invalid')
    names=[e.get('name') if isinstance(e,dict) else None for e in data['services']]
    require(len(names)==len(SERVICES) and sorted(names)==sorted(SERVICES),'SDK5 service set invalid')
    return {'schema':1,'operation':'sdk5-reconcile','deployment_id':ids[0],'uri':URI,'services':list(SERVICES)}
def dispatch():
    c=Connection('localhost',timeout=8)
    try:
        c.request('POST','/deployments',BODY,{'Content-Type':'application/json','Accept':'application/json'})
        response=c.getresponse();raw=response.read(LIMIT+1)
        require(response.status==201 and len(raw)<=LIMIT,'registration outcome unknown')
        data=parse(raw);ident=data.get('id') if isinstance(data,dict) else None
        require(isinstance(ident,str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',ident) is not None and isinstance(data.get('services'),list),'registration result invalid')
        names=[e.get('name') if isinstance(e,dict) else None for e in data['services']]
        require(len(names)==len(SERVICES) and sorted(names)==sorted(SERVICES),'registration service set invalid')
    finally:c.close()
    metadata=get('/deployments/'+ident)
    require(isinstance(metadata,dict) and metadata.get('id')==ident and uri_matches(metadata.get('uri')) and isinstance(metadata.get('services'),list),'registration metadata invalid')
    names=[e.get('name') if isinstance(e,dict) else None for e in metadata['services']]
    require(len(names)==len(SERVICES) and sorted(names)==sorted(SERVICES),'registration metadata service set invalid')
    return {'schema':1,'operation':'sdk5-registered','deployment_id':ident,'uri':URI,'services':list(SERVICES)}
def main():
    require(len(sys.argv)==2 and sys.argv[1] in ('prezero','dispatch','reconcile'),'fixed operation required')
    identity();before=socket_identity();result={'prezero':prezero,'dispatch':dispatch,'reconcile':reconcile}[sys.argv[1]]();require(socket_identity()==before,'admin socket changed')
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
if __name__=='__main__':
    try:main()
    except Exception:
        print('fixed admin operation failed or outcome unknown',file=sys.stderr);sys.exit(1)
