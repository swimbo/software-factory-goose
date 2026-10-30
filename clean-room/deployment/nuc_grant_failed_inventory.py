#!/usr/bin/env python3
"""Read-only inventory of the single failed grant-sidecar installation."""
import hashlib,json,os,pathlib,re,selectors,stat,subprocess,time
NAME='software-factory-goose-grant-canary-'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LANG':'C'}

def registration_record(raw):
    if len(raw)>65536: raise ValueError('journal output exceeds bound')
    matches=[]
    for line in raw.splitlines():
        item=json.loads(line)
        message=item.get('MESSAGE')
        if not isinstance(message,str) or not message.startswith('GRANT_REGISTRATION '): continue
        invocation=item.get('_SYSTEMD_INVOCATION_ID')
        if item.get('_SYSTEMD_UNIT')!=NAME+'register.service' or not isinstance(invocation,str) or not re.fullmatch(r'[0-9a-f]{32}',invocation): raise ValueError('untrusted registration record')
        payload=json.loads(message.removeprefix('GRANT_REGISTRATION '))
        if not isinstance(payload,dict) or set(payload)!={'id','service_count'} or not isinstance(payload['id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',payload['id']) or type(payload['service_count']) is not int or payload['service_count']!=4: raise ValueError('invalid registration record')
        matches.append({'invocation_id':invocation,'deployment_id':payload['id'],'service_count':4})
    if len(matches)!=1: raise ValueError('registration result not unique')
    return matches[0]

def command(args):
    result=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
    if len(result.stdout)>262144 or len(result.stderr)>8192: raise ValueError('command output exceeds bound')
    return result.stdout

def journal_output():
    args=['/usr/bin/journalctl','--boot','-u',NAME+'register.service','--no-pager','-o','json','--output-fields=MESSAGE,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID']
    p=subprocess.Popen(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    output=bytearray(); deadline=time.monotonic()+15
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout,selectors.EVENT_READ)
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0: raise ValueError('journal timeout')
                if not selector.select(remaining): raise ValueError('journal timeout')
                chunk=os.read(p.stdout.fileno(),min(8192,65537-len(output)))
                if not chunk: break
                output.extend(chunk)
                if len(output)>65536: raise ValueError('journal output exceeds bound')
        if p.wait(timeout=max(.01,deadline-time.monotonic()))!=0: raise ValueError('journal unavailable')
        return bytes(output)
    finally:
        if p.poll() is None: p.kill(); p.wait()
        p.stdout.close()

def file_info(path):
    try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    except FileNotFoundError: return None
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size>100000000: raise ValueError('unexpected file')
        h=hashlib.sha256(); total=0
        while True:
            data=os.read(fd,65536)
            if not data: break
            total+=len(data); h.update(data)
        if total!=s.st_size: raise ValueError('file changed')
        return {'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'dev':s.st_dev,'ino':s.st_ino,'nlink':s.st_nlink,'size':total,'sha256':h.hexdigest()}
    finally: os.close(fd)

def inventory():
    if os.geteuid()!=0: raise ValueError('root required')
    paths=['/etc/software-factory-goose/grant-sidecar-started.json','/etc/software-factory-goose/grant-sidecar-complete.json','/etc/software-factory-goose/grant-bootstrap-complete','/etc/software-factory-goose/grant-runtime.json','/etc/software-factory-goose/grant-evidence.json','/usr/local/libexec/software-factory-goose/private-grant-sidecar','/usr/local/libexec/software-factory-goose/private-grant-register.py']
    units=[NAME+x for x in ('intake.socket','worker.socket','launch.socket','runtime.service','register.service')]
    paths += ['/etc/systemd/system/'+u for u in units]
    states={}
    for u in units:
        raw=command(['/usr/bin/systemctl','show',u,'--property=Names,LoadState,ActiveState,SubState,Result,ExecMainStatus,FragmentPath,DropInPaths,MainPID','--no-pager'])
        states[u]=dict(line.split('=',1) for line in raw.decode().splitlines())
    sockets={}
    for name in ('grant-intake.sock','grant-worker.sock','launch-grant.sock'):
        try:
            s=os.lstat('/run/software-factory-goose/'+name); sockets[name]={'mode':stat.S_IMODE(s.st_mode),'type':stat.S_IFMT(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'dev':s.st_dev,'ino':s.st_ino}
        except FileNotFoundError: sockets[name]=None
    raw=journal_output()
    return {'files':{p:file_info(p) for p in paths},'units':states,'sockets':sockets,'registration':registration_record(raw)}

if __name__=='__main__': print(json.dumps(inventory(),sort_keys=True))
