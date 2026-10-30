#!/usr/bin/env python3
"""One-shot trusted UID probe of the private canary; not worker containment.

Run --before only after reviewed recovery. Operator restarts the exact runtime
unit separately, then run --after once. A timeout or inconsistent result is
unknown: preserve the private evidence directory and never retry automatically.
"""
import hashlib,json,os,pathlib,socket,stat,subprocess,sys,uuid
ROOT=pathlib.Path('/tmp/sfactory-private-runtime-acceptance-20261030')
SFCTL='/usr/local/libexec/software-factory-goose/sfctl'
SFCTL_SHA='d83b2d93a8cc4b7fddce6c435bafbbdf2b4b2c925d52a713398c4282729f1c6e'
IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
DOCKER=['/usr/bin/docker','--host','unix:///run/docker.sock']
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C'}
WORKER='/run/software-factory-goose/worker.sock'
INTAKE='/run/software-factory-goose/intake.sock'
INTENT='01ARZ3NDEKTSV4RRFFQ69G5FAZ';TASK='01ARZ3NDEKTSV4RRFFQ69G5FAY';PULL='01ARZ3NDEKTSV4RRFFQ69G5FAW'
REQUEST={'schema_version':1,'repository':'fixture','target_ref':'refs/heads/main','base_revision':'a'*40,'intent':'build fixture','acceptance_criteria':['passes fixture']}
LABEL='org.software-factory.private-acceptance'

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def command(args,timeout=15):
 p=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
 require(len(p.stdout)<=65536 and len(p.stderr)<=65536,'output limit; outcome unknown')
 return p

def save(name,value):
 data=json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n';fd=os.open(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short evidence write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def guard():
 p=command(DOCKER+['info','--format','{{.ID}}']);require(p.returncode==0 and p.stdout.decode().strip()=='56d25a60-5f64-4212-b904-e750067ac6a5','docker daemon identity mismatch')
 p=command(DOCKER+['version','--format','{{.Server.GitCommit}}']);require(p.returncode==0 and p.stdout.decode().strip()=='3ce5872','docker version mismatch')
 p=command(['/usr/bin/systemctl','show','docker.service','-p','MainPID','--value']);require(p.returncode==0 and p.stdout.decode().strip()=='2145','docker PID mismatch')
 p=command(DOCKER+['inspect','04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062']);require(p.returncode==0,'retained guard missing')
 o=json.loads(p.stdout)[0];require(o['Name']=='/sf-owner-224a71d2db764249aa6cade3c1b39c80' and o['State']['Status']=='created' and o['State']['Pid']==0 and (o['Config']['Labels'] or {}).get('org.software-factory.escape-spike')=='224a71d2db764249aa6cade3c1b39c80','retained guard changed')
 for service in ('docker.service','hermes-dashboard.service','hermes-gateway.service'):
  p=command(['/usr/bin/systemctl','is-active',service]);require(p.returncode==0 and p.stdout.strip()==b'active','preserved service unavailable')

def running_limits():
 units={'host-net.service':(64*1024**2,16,50),'net.service':(64*1024**2,16,50),
        'postgres.service':(1024**3,128,200),'restate.service':(4*1024**3,256,200),
        'runtime.service':(512*1024**2,128,100)}
 observed={}
 for suffix,(memory,pids,cpu) in units.items():
  name='software-factory-goose-private-'+suffix
  p=command(['/usr/bin/systemctl','show',name,'--property=ActiveState,MainPID,ControlGroup','--no-pager'])
  require(p.returncode==0,'unit state unavailable');props=dict(line.split('=',1) for line in p.stdout.decode().splitlines())
  require(props.get('ActiveState')=='active' and int(props.get('MainPID','0'))>1,'unit not active')
  cgroup='/system.slice/'+name;require(props.get('ControlGroup')==cgroup,'unit cgroup scope mismatch')
  base=pathlib.Path('/sys/fs/cgroup'+cgroup);st=os.stat(base);require(st.st_uid==0,'unit cgroup owner mismatch')
  before=(st.st_dev,st.st_ino)
  memory_actual=(base/'memory.max').read_text().strip();pids_actual=(base/'pids.max').read_text().strip();quota=(base/'cpu.max').read_text().split()
  require(memory_actual==str(memory) and pids_actual==str(pids) and len(quota)==2 and quota[0].isdigit() and quota[1].isdigit() and int(quota[0])*100==int(quota[1])*cpu,'kernel resource limit mismatch')
  st=os.stat(base);require((st.st_dev,st.st_ino)==before,'unit cgroup identity changed')
  observed[name]={'pid':int(props['MainPID']),'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino}
 return observed


def client_check():
 fd=os.open(SFCTL,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o755 and s.st_nlink==1,'sfctl identity mismatch')
  h=hashlib.sha256()
  while True:
   b=os.read(fd,65536)
   if not b:break
   h.update(b)
  require(h.hexdigest()==SFCTL_SHA,'sfctl digest mismatch')
 finally:os.close(fd)

def cli(*args,expect_success):
 p=command([SFCTL,'--json','private',*args],timeout=15)
 require((p.returncode==0)==expect_success,'sfctl outcome unexpected')
 if not expect_success:require(b'status 403' in p.stderr,'sfctl denial not established')
 if expect_success:
  value=json.loads(p.stdout);require(value.get('intent_id')==INTENT,'sfctl reply scope mismatch')
 return p.returncode

WORKER_CODE=r'''import hashlib,http.client,json,os,socket,sys
uid=int(sys.argv[1]);mode=sys.argv[2]
if os.geteuid()!=uid:raise RuntimeError('UID mismatch')
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10)
try:s.connect('/worker.sock')
except PermissionError:
 if mode=='deny':print(json.dumps({'denied':True}));sys.exit(0)
 raise
if mode=='deny':raise RuntimeError('unexpected filesystem access')
body=json.dumps({'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','ttl_ms':300000},separators=(',',':')).encode()
s.sendall(b'POST /pull HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
response=http.client.HTTPResponse(s);response.begin();payload=response.read(65537)
if len(payload)>65536:raise RuntimeError('response limit')
status=response.status;out={'status':status}
if status==200:
 obj=json.loads(payload);a=obj['Assigned'];lease=a['lease']
 if not (a['work_package_id']=='01ARZ3NDEKTSV4RRFFQ69G5FAY' and a['spec']=={'repository':'fixture','base_revision':'a'*40} and lease['worker_id']=='fixture-worker' and lease['attempt']==1):raise RuntimeError('assignment mismatch')
 out['digest']=hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()
print(json.dumps(out,sort_keys=True))'''

def probe(uid,mode,index):
 token=uuid.uuid4().hex;name='sfactory-private-probe-'+token;save('probe-'+index+'-intent.json',{'name':name,'token':token,'uid':uid,'mode':mode})
 guard();before=os.lstat(WORKER);require(stat.S_ISSOCK(before.st_mode) and before.st_uid==0 and before.st_gid==2001 and stat.S_IMODE(before.st_mode)==0o660,'worker socket identity mismatch')
 args=DOCKER+['create','--pull=never','--name',name,'--label',LABEL+'='+token,'--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=16','--memory=128m','--cpus=0.5','--user',f'{uid}:{uid}','--mount',f'type=bind,src={WORKER},dst=/worker.sock,readonly','--entrypoint','/usr/local/bin/python3',IMAGE,'-I','-B','-c',WORKER_CODE,str(uid),mode]
 p=command(args,timeout=30);require(p.returncode==0,'create failed or unknown; retain intent')
 cid=p.stdout.decode().strip();require(len(cid)==64 and all(c in '0123456789abcdef' for c in cid),'invalid container identity');save('probe-'+index+'-id.json',{'id':cid})
 p=command(DOCKER+['inspect',cid]);require(p.returncode==0,'container inspect unavailable');o=json.loads(p.stdout)[0];h=o['HostConfig'];mounts=o['Mounts']
 require(o['Id']==cid and o['Name']=='/'+name and o['Image']==IMAGE and (o['Config']['Labels'] or {}).get(LABEL)==token and o['State']['Status']=='created' and o['Config']['User']==f'{uid}:{uid}' and h['NetworkMode']=='none' and h['ReadonlyRootfs'] and not h['Privileged'] and set(h['CapDrop'] or [])=={'ALL'} and not h['CapAdd'] and 'no-new-privileges' in (h['SecurityOpt'] or []) and o['Config']['Entrypoint']==['/usr/local/bin/python3'] and o['Config']['Cmd']==['-I','-B','-c',WORKER_CODE,str(uid),mode] and not h['GroupAdd'] and h['Memory']==128*1024*1024 and h['PidsLimit']==16 and h['NanoCpus']==500000000 and h['RestartPolicy']['Name']=='no' and len(mounts)==1 and mounts[0]['Source']==WORKER and mounts[0]['Destination']=='/worker.sock' and not mounts[0]['RW'],'probe identity mismatch')
 # A timeout is unknown: retain exact ID, intent and container for explicit reconciliation.
 p=command(DOCKER+['start','--attach',cid],timeout=30);require(p.returncode==0,'probe execution failed or unknown')
 result=json.loads(p.stdout);guard()
 after=os.lstat(WORKER);require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),'worker socket changed')
 p=command(DOCKER+['inspect',cid]);require(p.returncode==0,'probe cleanup identity unavailable');o=json.loads(p.stdout)[0]
 require(o['Id']==cid and o['Name']=='/'+name and (o['Config']['Labels'] or {}).get(LABEL)==token and o['State']['Status']=='exited','probe cleanup identity mismatch')
 p=command(DOCKER+['rm',cid]);require(p.returncode==0 and p.stdout.decode().strip()==cid,'probe cleanup unresolved');save('probe-'+index+'-clean.json',{'id':cid,'removed':True})
 return result

def run_before():
 os.mkdir(ROOT,0o700);save('intent.json',{'scope':'fixed private canary intake and UID worker; no launch','task':TASK,'intent':INTENT})
 guard();client_check();limits=running_limits()
 request=ROOT/'request.json';fd=os.open(request,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(json.dumps(REQUEST).encode());f.flush();os.fsync(f.fileno())
 require(probe(2002,'deny','wrong-uid')=={'denied':True},'wrong UID was not denied')
 require(probe(2001,'pull','unqualified').get('status')==409,'unqualified work was not denied')
 cli('submit','--id','01ARZ3NDEKTSV4RRFFQ69G5FAX','--request',str(request),expect_success=False)
 save('submit-started.json',{'intent':INTENT})
 cli('submit','--id',INTENT,'--request',str(request),expect_success=True)
 cli('submit','--id',INTENT,'--request',str(request),expect_success=True)
 cli('inspect',INTENT,expect_success=True)
 save('pull-started.json',{'request_id':PULL})
 a=probe(2001,'pull','pull-a');b=probe(2001,'pull','pull-b')
 require(a.get('status')==200 and a==b and len(a.get('digest',''))==64,'pull replay mismatch')
 save('before-complete.json',{'digest':a['digest'],'task':TASK,'pull':PULL,'limits':limits})
 print('PASS: private CLI intake and UID-scoped worker claim/replay; awaiting runtime restart')

def run_after():
 st=os.lstat(ROOT);require(stat.S_ISDIR(st.st_mode) and st.st_uid==1000 and stat.S_IMODE(st.st_mode)==0o700,'acceptance root mismatch')
 before=json.loads((ROOT/'before-complete.json').read_bytes());save('after-started.json',{'pull':PULL});guard();client_check();limits=running_limits()
 require(limits['software-factory-goose-private-runtime.service']['pid']!=before['limits']['software-factory-goose-private-runtime.service']['pid'],'runtime restart not observed')
 for name in ('software-factory-goose-private-net.service','software-factory-goose-private-postgres.service','software-factory-goose-private-restate.service'):
  require(limits[name]==before['limits'][name],'supporting service identity changed')
 cli('inspect',INTENT,expect_success=True);a=probe(2001,'pull','pull-after')
 require(a.get('status')==200 and a.get('digest')==before['digest'],'post-restart claim replay mismatch')
 save('after-complete.json',{'task':TASK,'pull':PULL});print('PASS: private intake and exact worker claim survived runtime restart')

if __name__=='__main__':
 require(os.getuid()==1000 and os.geteuid()==1000,'trusted operator UID required')
 if sys.argv==[sys.argv[0],'--before']:run_before()
 elif sys.argv==[sys.argv[0],'--after']:run_after()
 else:raise SystemExit('expected --before or --after')
