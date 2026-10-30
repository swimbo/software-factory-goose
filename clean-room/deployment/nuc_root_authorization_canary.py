#!/usr/bin/env python3
"""Review-only fixed public fixture for native root/UID2000 authorization tests.

Synthetic names are disjoint from real generations. No provider, journal, Docker,
credentials or live task state are touched. Partial outcomes are retained.
"""
import hashlib,json,os,pathlib,stat,subprocess,sys
import nuc_evidence_reader_canary as guard

ROOT=pathlib.Path('/etc/software-factory-goose/finalization-authorization')
INTENT=ROOT.parent/'authorization-canary.intent'
PUB=pathlib.Path('/usr/local/libexec/software-factory-goose/root_authorization_publisher_canary')
READER=pathlib.Path('/usr/local/libexec/software-factory-goose/root_authorization_reader_canary')
PUB_SHA='9a2c8d9cd3f3c9f4b174595096b4cce715ebdbc42f9f6e7f0c7114312d198df4'
READER_SHA='9572af6fe7086f34479ea70ae1e20539c5a3c510382086c66158bfaf8cd852e9'
TASK='67J0MV0HTHADF1K7JP9F9XC578'
GENS=('5CDTQ2S41Z8SMJG8V1JTJGSR4P','76VR8GQDSWWEC5YDNEP0FG61XT','6ZDKDZWDQQMWR3XZAD9J7TNRFM','117WW1Z87X76TZJSVN11Q6FH0F')
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C'}
UNITS=('sfactory-auth-valid-canary','sfactory-auth-crash-canary','sfactory-auth-reader-canary','sfactory-auth-worker-canary')

def pin(path,digest):
    guard.require(len(digest)==64 and all(c in '0123456789abcdef' for c in digest),'binary unpinned')
    guard.fixed_tool(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());guard.require(st.st_size<=64*1024*1024,'binary oversized')
        guard.require(hashlib.sha256(f.read(64*1024*1024+1)).hexdigest()==digest,'binary digest mismatch')

def plan():
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required')
    guard.ancestors(ROOT);guard.require(not os.path.lexists(INTENT),'prior intent retained')
    if os.path.lexists(ROOT):
        st=ROOT.lstat();guard.require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o755,'authorization directory mismatch');guard.no_acl(ROOT)
        for g in GENS:
            for suffix in ('.lock','.pending','.authorization.json','.complete.json'):
                guard.require(not os.path.lexists(ROOT/(g+suffix)),'synthetic fixture occupied')
    for tool in (pathlib.Path('/usr/bin/systemd-run'),pathlib.Path('/usr/bin/systemctl'),pathlib.Path('/usr/bin/systemd-analyze')):guard.fixed_tool(tool)
    pin(PUB,PUB_SHA);pin(READER,READER_SHA)
    paths=subprocess.run(['/usr/bin/systemd-analyze','--system','unit-paths'],env=ENV,capture_output=True,timeout=5,check=True).stdout.decode().splitlines()
    guard.require(paths and len(paths)<=64 and all(pathlib.Path(p).is_absolute() for p in paths),'unit paths unavailable')
    for name in UNITS:
        unit=name+'.service'
        probe=subprocess.run(['/usr/bin/systemctl','show',unit,'-p','LoadState','--value'],env=ENV,capture_output=True,timeout=5,check=True)
        guard.require(probe.stdout.strip() in (b'',b'not-found'),'synthetic unit already exists')
        candidates=[unit,unit+'.d','service.d']+[name[:index+1]+'.service.d' for index,char in enumerate(name) if char=='-']
        for parent in paths:
            for candidate in candidates:guard.require(not os.path.lexists(pathlib.Path(parent)/candidate),'unit path or drop-in occupied')
    return {'schema':1,'purpose':'synthetic-authorization-only','dir':str(ROOT),'generations':list(GENS),'task':TASK,'publisher_sha256':PUB_SHA,'reader_sha256':READER_SHA,'lock':'root:2000 0440','authorization':'root:root 0444','features':'root-authorization-canary only on synthetic publisher','retained':True}

def syncdir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def create(path,data,mode,gid=0):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    with os.fdopen(fd,'wb') as f:
        os.fchown(f.fileno(),0,gid);os.fchmod(f.fileno(),mode);f.write(data);f.flush();os.fsync(f.fileno())
    syncdir(path.parent)

def run_unit(name,uid,binary,args):
    command=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--unit='+name,'--property=User='+str(uid),'--property=Group='+str(uid),'--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=NoNewPrivileges=yes','--property=PrivateNetwork=yes','--property=MemoryMax=128M','--property=TasksMax=16','--property=CPUQuota=50%','--property=RuntimeMaxSec=30s',str(binary),*args]
    return subprocess.run(command,env=ENV,capture_output=True,timeout=40,check=False)

def apply(reviewed):
    guard.require(plan()==reviewed,'reviewed scope changed')
    create(INTENT,(json.dumps(reviewed,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
    if not os.path.lexists(ROOT):
        ROOT.mkdir(mode=0o755);os.chmod(ROOT,0o755,follow_symlinks=False);syncdir(ROOT.parent)
    for g in GENS:create(ROOT/(g+'.lock'),b'',0o440,2000)
    unsafe={'schema':1,'task_id':TASK,'generation':GENS[2],'request_sha256':'a'*64}
    raw=json.dumps(unsafe,separators=(',',':')).encode()
    create(ROOT/(GENS[2]+'.authorization.json'),raw,0o644)
    create(ROOT/(GENS[2]+'.complete.json'),raw,0o444)
    valid=run_unit('sfactory-auth-valid-canary',0,PUB,['--valid'])
    guard.require(valid.returncode==0 and valid.stdout==b'PASS: synthetic authorization published\n','valid publisher failed')
    crash=run_unit('sfactory-auth-crash-canary',0,PUB,['--crash'])
    guard.require(crash.returncode!=0 and b'SFACTORY_CANARY_AUTH_FSYNC_BEFORE_PARENT_FSYNC\n' in crash.stderr and os.path.isfile(ROOT/(GENS[1]+'.pending')) and os.path.isfile(ROOT/(GENS[1]+'.authorization.json')) and not os.path.lexists(ROOT/(GENS[1]+'.complete.json')),'crash point unresolved')
    reader=run_unit('sfactory-auth-reader-canary',2000,READER,[])
    guard.require(reader.returncode==0 and reader.stdout==b'PASS: UID2000 exact authorization accepted; changed digest, pending, unsafe mode and missing authorization refused; no capabilities; no-new-privileges\n','SDK reader failed')
    worker=run_unit('sfactory-auth-worker-canary',2001,READER,['--worker'])
    guard.require(worker.returncode==0 and worker.stdout==b'PASS: UID2001 denied authorization lock; no capabilities; no-new-privileges\n','worker denial failed')
    result={'schema':1,'result':'pass','crash_barrier':'auth-file-fsync-before-parent-fsync','sdk_pending':'denied','worker_lock':'denied','records_retained':True}
    create(ROOT.parent/'authorization-canary.result',(json.dumps(result,sort_keys=True)+'\n').encode(),0o600)
    return result

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
if __name__=='__main__':
    if sys.argv==[sys.argv[0],'plan']:
        value=plan();print(json.dumps({'plan':value,'sha256':digest(value)},sort_keys=True))
    elif len(sys.argv)==3 and sys.argv[1]=='apply':
        value=plan();guard.require(sys.argv[2]==digest(value),'reviewed plan digest mismatch');print(json.dumps(apply(value),sort_keys=True))
    else:raise RuntimeError('expected plan or apply with plan digest')
