#!/usr/bin/env python3
"""Fixed, synthetic-only root journal fixture; never a production publisher.

Draft only: requires review and exact Linux binary pins before bridge integration.
The operator runner owns disposable Postgres/Restate; this helper owns one SDK unit.
"""
import hashlib,json,os,pathlib,re,socket,stat,subprocess,sys,time
import nuc_evidence_reader_canary as guard
import nuc_root_authorization_canary as auth

G='01ARZ3NDEKTSV4RRFFQ69G5FAM'
BASE=pathlib.Path('/etc/software-factory-goose/finalization-authorization')
REQUEST=BASE/'journal-fixture-request.json'
INTENT=BASE.parent/'journal-fixture.intent'
SDK=pathlib.Path('/usr/local/libexec/software-factory-goose/finalization_journal_fixture')
PUBLISHER=pathlib.Path('/usr/local/libexec/software-factory-goose/root_authorization_journal_fixture')
ATTESTOR=pathlib.Path('/usr/local/libexec/software-factory-goose/finalization_pg_attestor.py')
ATTESTOR_SHA='3fad9b4f2c208a94c81ffe5842f85be12a5d927aa8ce54da1974d7b4221d5338'
UNIT='sfactory-finalization-journal-fixture.service'
UNIT_RECORD=BASE.parent/'journal-fixture.unit.json'
RESTART_UNIT='sfactory-finalization-journal-restart.service'
RESTART_RECORD=BASE.parent/'journal-fixture.restart-unit.json'
RESTART_INTENT=BASE.parent/'journal-fixture.restart-intent.json'
START_DONE=BASE.parent/'journal-fixture.start-complete.json'
RESTART_DONE=BASE.parent/'journal-fixture.restart-complete.json'
SDK_PORT=48291
PG_PORT=48292
# Must be replaced with independently verified build hashes before use.
SDK_SHA='a7f180b77005563106bf630a6b7d5708f358edb12b85ac27f1e61d7c4cd8cf72'
PUBLISHER_SHA='a4b538b4f9837d2b596b97aa667b0601890e79ffa3dcc33a70ae3cb5b712919c'
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C'}

def run(command):
    return subprocess.run(command,env=ENV,capture_output=True,timeout=15,check=True)

def plan():
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required')
    guard.require(len(SDK_SHA)==64,'SDK binary pin not supplied')
    guard.ancestors(BASE); auth.pin(SDK,SDK_SHA); auth.pin(PUBLISHER,PUBLISHER_SHA); auth.pin(ATTESTOR,ATTESTOR_SHA)
    for path in (INTENT,UNIT_RECORD,RESTART_RECORD,RESTART_INTENT,START_DONE,RESTART_DONE,REQUEST,*(BASE/(G+s) for s in ('.lock','.pending','.authorization.json','.complete.json'))):
        guard.require(not os.path.lexists(path),'fixture path occupied')
    for tool in (pathlib.Path('/usr/bin/systemctl'),pathlib.Path('/usr/bin/systemd-run'),pathlib.Path('/usr/bin/systemd-analyze'),pathlib.Path('/usr/bin/python3.13')): guard.fixed_tool(tool)
    paths=run(['/usr/bin/systemd-analyze','--system','unit-paths']).stdout.decode().splitlines()
    guard.require(paths and len(paths)<=64 and all(pathlib.Path(p).is_absolute() for p in paths),'unit paths unavailable')
    for unit in (UNIT,'sfactory-finalization-journal-publish.service','sfactory-finalization-pg-before.service','sfactory-finalization-pg-after.service','sfactory-finalization-journal-restart.service','sfactory-finalization-pg-restart-before.service','sfactory-finalization-pg-restart-after.service'):
        name=unit.removesuffix('.service')
        for parent in paths:
            for candidate in [unit,unit+'.d','service.d']+[name[:i+1]+'.service.d' for i,c in enumerate(name) if c=='-']:
                guard.require(not os.path.lexists(pathlib.Path(parent)/candidate),'unit or drop-in occupied')
        state=run(['/usr/bin/systemctl','show',unit,'-p','LoadState','--value']).stdout.strip()
        guard.require(state in (b'',b'not-found'),'fixture unit occupied')
    state=run(['/usr/bin/systemctl','show',UNIT,'-p','LoadState','--value']).stdout.strip()
    guard.require(state in (b'',b'not-found'),'fixture unit occupied')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',SDK_PORT))
    return {'schema':1,'purpose':'synthetic-direct-journal-authorization-only','task':G,'generation':G,'sdk_sha256':SDK_SHA,'publisher_sha256':PUBLISHER_SHA,'attestor_sha256':ATTESTOR_SHA,'sdk_port':SDK_PORT,'pg_port':PG_PORT,'unit':UNIT,'request':str(REQUEST),'production_registry_gate':False}

def digest(plan_value):
    return hashlib.sha256(json.dumps(plan_value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def start(reviewed):
    guard.require(plan()==reviewed,'fixture plan changed')
    auth.create(INTENT,(json.dumps(reviewed,sort_keys=True)+'\n').encode(),0o600)
    auth.create(BASE/(G+'.lock'),b'',0o440,2000)
    before=attest_pg('sfactory-finalization-pg-before')
    launch_sdk(UNIT,UNIT_RECORD,before,'sfactory-finalization-pg-after')
    auth.create(START_DONE,b'{"schema":1,"started":true}\n',0o444)
    return {'status':'started','unit':UNIT,'intent_retained':True}

def launch_sdk(unit,record,before,post_attestor):
    command=['/usr/bin/systemd-run','--quiet','--unit='+unit.removesuffix('.service'),'--property=Type=exec','--property=User=2000','--property=Group=2000','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=NoNewPrivileges=yes','--property=MemoryMax=512M','--property=TasksMax=32','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--setenv=TOKIO_WORKER_THREADS=2','--property=RuntimeMaxSec=900s','--setenv=SFACTORY_FIXTURE_DATABASE_URL=postgres://sfactory@127.0.0.1:48292/sfactory_verification',str(SDK),'127.0.0.1:48291']
    run(command)
    info=unit_info(unit)
    guard.require(info.get('LoadState')=='loaded' and info.get('ActiveState')=='active' and info.get('User')=='2000' and info.get('Group')=='2000' and info.get('NoNewPrivileges')=='yes' and info.get('InvocationID') and info.get('MainPID','0').isdigit() and int(info['MainPID'])>0 and re.fullmatch(r'[0-9a-f]{32}',info['InvocationID']) and re.fullmatch(r'\{ path='+re.escape(str(SDK))+r' ; argv\[\]='+re.escape(str(SDK))+r' 127\.0\.0\.1:48291 ; [^{}]*\}',info.get('ExecStart','')) is not None, 'fixture identity unresolved')
    auth.create(record,(json.dumps(info,sort_keys=True)+'\n').encode(),0o600)
    deadline=time.monotonic()+5
    while True:
        try:
            now=unit_info(unit)
            guard.require(now.get('ActiveState')=='active' and now.get('MainPID')==info['MainPID'] and now.get('InvocationID')==info['InvocationID'] and now.get('ExecStart')==info['ExecStart'],'unit identity changed')
            verify_process(now)
            break
        except (OSError,RuntimeError):
            if time.monotonic()>=deadline:raise
            time.sleep(.05)
    guard.require(attest_pg(post_attestor)==before,'postgres identity changed across SDK start')

def attest_pg(name):
    command=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--unit='+name,'--property=User=1000','--property=Group=1000','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=NoNewPrivileges=yes','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=30s','/usr/bin/python3.13','-I','-B',str(ATTESTOR)]
    p=subprocess.run(command,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40,check=False)
    guard.require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'postgres attestation failed or ambiguous')
    value=json.loads(p.stdout);guard.require(set(value)=={'schema','status','pid','starttime','socket_inode','root_dev','root_ino','system_identifier'} and value['schema']==1 and value['status']=='attested','postgres attestation invalid')
    return value

def unit_info(unit=UNIT):
    names=['LoadState','ActiveState','User','Group','NoNewPrivileges','InvocationID','MainPID','ExecStart','DropInPaths']
    raw=run(['/usr/bin/systemctl','show',unit,*sum((['-p',n] for n in names),[])]).stdout.decode()
    result=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
    guard.require(not result.get('DropInPaths'),'fixture drop-in present')
    return result

def verify_process(info):
    pid=int(info['MainPID'])
    status=pathlib.Path('/proc')/str(pid)/'status'
    data=status.read_text().splitlines()
    fields=dict(line.split(':',1) for line in data if ':' in line)
    guard.require(fields.get('Uid','').split()==['2000']*4 and fields.get('Gid','').split()==['2000']*4 and fields.get('NoNewPrivs','').strip()=='1','fixture process identity mismatch')
    for name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'):
        guard.require(fields.get(name,'').strip()=='0000000000000000','fixture capability mismatch')

def owned_unit(unit=UNIT,record=UNIT_RECORD):
    guard.ancestors(record)
    st=record.lstat()
    guard.require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=16384,'unit record unsafe')
    guard.no_acl(record)
    old=json.loads(record.read_bytes())
    now=unit_info(unit)
    guard.require(now.get('LoadState')=='loaded' and now.get('ActiveState')=='active' and all(now.get(k)==old.get(k) and now.get(k) for k in ('InvocationID','MainPID','ExecStart','User','Group','NoNewPrivileges')),'fixture unit identity changed')
    verify_process(now)

STAGED_REQUEST=pathlib.Path('/tmp/sfactory-finalization-journal-fixture-request.json')
def staged_request():
    fd=os.open(STAGED_REQUEST,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno())
        guard.require(stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_gid==1000 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=65536,'fixture request metadata')
        raw=f.read(65537);after=os.fstat(f.fileno())
        guard.require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==before.st_size,'fixture request changed')
    def pairs(values):
        out={}
        for key,value in values:
            guard.require(key not in out,'duplicate field');out[key]=value
        return out
    request=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON')))
    scope=request['reservation']['scope']
    guard.require(request['reservation']['generation']==G and scope['generation']==G and scope['task_id']==G,'wrong synthetic scope')
    return raw

def publish(expected_sha256=None):
    guard.require(os.geteuid()==0 and os.getegid()==0 and INTENT.is_file(),'fixture intent missing')
    auth.pin(PUBLISHER,PUBLISHER_SHA)
    owned_unit()
    raw=staged_request()
    guard.require(expected_sha256 is not None and hashlib.sha256(raw).hexdigest()==expected_sha256,'reviewed request changed')
    auth.create(REQUEST,raw,0o600)
    result=auth.run_unit('sfactory-finalization-journal-publish',0,PUBLISHER,[])
    guard.require(result.returncode==0 and result.stdout==b'PASS: fixed synthetic journal authorization published\n','publication unresolved; retain all records')
    return {'status':'published','records_retained':True}

def stop(unit=UNIT,record=UNIT_RECORD):
    guard.require(os.geteuid()==0 and os.getegid()==0 and INTENT.is_file(),'fixture intent missing')
    owned_unit(unit,record)
    run(['/usr/bin/systemctl','stop',unit])
    properties=run(['/usr/bin/systemctl','show',unit,'-p','ActiveState','-p','MainPID','-p','Job']).stdout.decode().splitlines()
    guard.require('ActiveState=inactive' in properties and 'MainPID=0' in properties and 'Job=' in properties,'fixture unit stop unresolved')
    return {'status':'stopped','records_retained':True}


def restart():
    guard.require(not os.path.lexists(RESTART_INTENT) and not os.path.lexists(RESTART_RECORD) and not os.path.lexists(RESTART_DONE),'restart occupied')
    auth.create(RESTART_INTENT,b'{"schema":1,"restart":true}\n',0o600)
    stop()
    before=attest_pg('sfactory-finalization-pg-restart-before')
    launch_sdk(RESTART_UNIT,RESTART_RECORD,before,'sfactory-finalization-pg-restart-after')
    auth.create(RESTART_DONE,b'{"schema":1,"restarted":true}\n',0o444)
    return {'status':'restarted','unit':RESTART_UNIT,'records_retained':True}

def phase_plan(phase):
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required')
    if phase=='start': return {'phase':phase,'fixture':plan()}
    guard.require(phase in ('publish','restart','stop','stop-restarted'),'invalid fixed phase')
    old=recorded_plan_from_root()
    unit,record=(RESTART_UNIT,RESTART_RECORD) if phase=='stop-restarted' else (UNIT,UNIT_RECORD)
    owned_unit(unit,record)
    value={'phase':phase,'fixture_sha256':digest(old),'unit':unit}
    if phase=='publish':
        guard.require(not os.path.lexists(REQUEST),'request occupied')
        raw=staged_request();value.update(request_sha256=hashlib.sha256(raw).hexdigest(),request_size=len(raw))
    if phase=='restart':
        guard.require(not os.path.lexists(RESTART_INTENT) and not os.path.lexists(RESTART_RECORD) and not os.path.lexists(RESTART_DONE),'restart occupied')
    return value

def recorded_plan_from_root():
    fd=os.open(INTENT,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());guard.require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=16384,'unsafe intent')
        raw=f.read(16385);guard.require(len(raw)==st.st_size,'intent changed')
    guard.no_acl(INTENT);value=json.loads(raw)
    guard.require(value.get('task')==G and value.get('generation')==G and value.get('sdk_sha256')==SDK_SHA and value.get('publisher_sha256')==PUBLISHER_SHA,'intent mismatch')
    return value

def phase_apply(phase,reviewed):
    guard.require(phase_plan(phase)==reviewed,'phase plan changed')
    if phase=='start':return start(reviewed['fixture'])
    if phase=='publish':return publish(reviewed['request_sha256'])
    if phase=='restart':return restart()
    if phase=='stop':return stop()
    if phase=='stop-restarted':return stop(RESTART_UNIT,RESTART_RECORD)
    raise RuntimeError('invalid fixed phase')
