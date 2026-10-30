#!/usr/bin/env python3
"""Fixed read-only Restate deployment inspection inside the private namespace."""
import hashlib,http.client,json,os,re,sys
from urllib.parse import urlsplit
CONFIG='/etc/software-factory-goose/runtime.json'
CONFIG_SHA='53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6'

def summary(data, deployment_id):
    obj=json.loads(data)
    if not isinstance(obj,dict): raise ValueError('deployment response malformed')
    # Only structural metadata is emitted until the actual API schema is verified.
    result={'response_sha256':hashlib.sha256(data).hexdigest(),'top_level_fields':sorted(obj),'id_matches':obj.get('id')==deployment_id}
    uri=obj.get('uri')
    result['uri_type']=type(uri).__name__
    if isinstance(uri,str):
        parsed=urlsplit(uri)
        result['uri_matches']=(parsed.scheme=='http' and parsed.hostname=='127.0.0.1' and parsed.port==9082 and parsed.path in ('','/') and not parsed.query and not parsed.fragment and parsed.username is None and parsed.password is None)
    for field in ('services','uri','endpoint'):
        v=obj.get(field)
        if field=='services' and isinstance(v,list):
            if len(v)>32: raise ValueError('too many services')
            entries=[]
            for x in v:
                if not isinstance(x,dict):raise ValueError('service metadata malformed')
                handlers=x.get('handlers')
                names=list(handlers) if isinstance(handlers,dict) else [h.get('name') for h in handlers if isinstance(h,dict)] if isinstance(handlers,list) else []
                if any(not isinstance(n,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',n) for n in names):raise ValueError('handler metadata malformed')
                entries.append({'name':x.get('name'),'revision':x.get('revision'),'deployment_matches':x.get('deployment_id')==deployment_id,'handler_kind':type(handlers).__name__,'handler_names':sorted(names),'handler_fields':sorted(handlers[0]) if isinstance(handlers,list) and handlers and isinstance(handlers[0],dict) else []})
            result['service_entries']=entries
        elif isinstance(v,str) and v=='http://127.0.0.1:9082': result[field]='http://127.0.0.1:9082'
    return result

def main():
    if os.geteuid()!=2000 or len(sys.argv)!=2 or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',sys.argv[1]): raise ValueError('identity or ID invalid')
    fd=os.open(CONFIG,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd); data=os.read(fd,65537)
        if st.st_uid!=0 or st.st_gid!=0 or st.st_mode & 0o022 or len(data)>65536 or hashlib.sha256(data).hexdigest()!=CONFIG_SHA: raise ValueError('configuration mismatch')
    finally: os.close(fd)
    config=json.loads(data); ns=os.stat('/proc/self/ns/net')
    if (ns.st_dev,ns.st_ino)!=(config['namespace_dev'],config['namespace_ino']) or (ns.st_dev,ns.st_ino)==(config['host_namespace_dev'],config['host_namespace_ino']): raise ValueError('namespace mismatch')
    c=http.client.HTTPConnection('127.0.0.1',9070,timeout=10)
    try:
        c.request('GET','/deployments/'+sys.argv[1],headers={'Accept':'application/json','Connection':'close'})
        response=c.getresponse(); body=response.read(65537)
        if response.status!=200 or len(body)>65536: raise ValueError('deployment inspection unavailable')
        print(json.dumps(summary(body,sys.argv[1]),sort_keys=True))
    finally:c.close()
if __name__=='__main__':main()
