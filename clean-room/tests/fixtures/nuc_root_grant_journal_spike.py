#!/usr/bin/env python3
"""Disposable real Restate/PG + Rust UID0 Unix grant adapter; never touches live journal.

Fixed trusted Docker clients mount only the fixture socket. A create/start timeout
retains the task-owned directory, intent and exact ID (when known), without retry.
"""
import hashlib,json,os,pathlib,shutil,socket,subprocess,sys,tempfile,time,urllib.error,urllib.request,uuid
BASE=pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX');PG=pathlib.Path('/usr/local/libexec/software-factory-goose/postgresql17')
RESTATE=pathlib.Path('/tmp/sfactory-gate-linux.X4ZjF1LB/restate-server');SDK=BASE/'target/debug/examples/launch_reservation_fixture';GATE=BASE/'target/debug/examples/root_grant_adapter_fixture'
IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937';DOCKER=['/usr/bin/docker','--host','unix:///run/docker.sock'];LABEL='org.software-factory.grant-journal-probe'
ENV={'PATH':'/usr/bin:/bin','HOME':'/tmp','LANG':'C','LD_LIBRARY_PATH':str(PG/'lib')}
TASK='01ARZ3NDEKTSV4RRFFQ69G5FAY';INTENT='01ARZ3NDEKTSV4RRFFQ69G5FAZ'

def require(x,msg):
 if not x:raise RuntimeError(msg)
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def cmd(args,timeout=20):
 p=subprocess.run(list(map(str,args)),env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
 require(len(p.stdout)<=65536 and len(p.stderr)<=65536,'output bound')
 return p
def save(root,name,obj):
 data=json.dumps(obj,sort_keys=True).encode()+b'\n';fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def post(url,value):
 req=urllib.request.Request(url,data=None if value is None else json.dumps(value).encode(),headers={} if value is None else {'content-type':'application/json'},method='POST')
 try:
  with urllib.request.urlopen(req,timeout=10) as r:
   b=r.read(262145);require(len(b)<=262144,'response limit');return r.status,json.loads(b) if b else None
 except urllib.error.HTTPError as e:return e.code,None
def stop(p):
 if p and p.poll() is None:
  p.terminate()
  try:p.wait(timeout=15)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
def guard():
 p=cmd(DOCKER+['info','--format','{{.ID}}']);require(p.returncode==0 and p.stdout.decode().strip()=='56d25a60-5f64-4212-b904-e750067ac6a5','daemon mismatch')
 p=cmd(DOCKER+['version','--format','{{.Server.GitCommit}}']);require(p.returncode==0 and p.stdout.decode().strip()=='3ce5872','daemon commit mismatch')
 p=cmd(['/usr/bin/systemctl','show','docker.service','-p','MainPID','--value']);require(p.returncode==0 and p.stdout.decode().strip()=='2145','daemon PID mismatch')
 p=cmd(DOCKER+['inspect','04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062']);require(p.returncode==0,'guard missing');o=json.loads(p.stdout)[0]
 require(o['Name']=='/sf-owner-224a71d2db764249aa6cade3c1b39c80' and o['State']['Status']=='created' and o['State']['Pid']==0 and (o['Config']['Labels'] or {}).get('org.software-factory.escape-spike')=='224a71d2db764249aa6cade3c1b39c80','guard changed')
CLIENT=r'''import hashlib,http.client,json,os,socket,sys
uid=int(sys.argv[1]);mode=sys.argv[2]
if os.geteuid()!=uid:raise RuntimeError('UID mismatch')
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);s.connect('/grant.sock')
gen='other' if mode=='wrong' else 'owned-generation';body=json.dumps({'generation':gen},separators=(',',':')).encode()
if mode=='partial':
 s.sendall(b'POST /reserve HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n')
 r=http.client.HTTPResponse(s);r.begin();print(json.dumps({'status':r.status}));sys.exit(0)
s.sendall(b'POST /reserve HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
if mode=='lost':
 if s.recv(1)!=b'H':raise RuntimeError('no response')
 print(json.dumps({'lost_ack':True}));sys.exit(0)
r=http.client.HTTPResponse(s);r.begin();raw=r.read(16385)
if len(raw)>16384:raise RuntimeError('response limit')
out={'status':r.status}
if r.status==200:
 grant=json.loads(raw);scope=grant['scope']
 if not (scope['task_id']=='01ARZ3NDEKTSV4RRFFQ69G5FAY' and scope['worker_id']=='fixture-worker' and scope['generation']=='owned-generation' and scope['catalog_sha256']=='b'*64 and grant['generation']=='owned-generation' and grant['attempt']==1):raise RuntimeError('scope mismatch')
 out['digest']=hashlib.sha256(json.dumps(grant,sort_keys=True,separators=(',',':')).encode()).hexdigest()
print(json.dumps(out,sort_keys=True))'''
def client(root,index,uid,mode):
 guard();token=uuid.uuid4().hex;name='sfactory-grant-probe-'+token;save(root,'client-'+index+'-intent.json',{'name':name,'token':token,'uid':uid,'mode':mode})
 path=root/'grant.sock';st=os.lstat(path)
 p=cmd(DOCKER+['create','--pull=never','--name',name,'--label',LABEL+'='+token,'--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=16','--memory=128m','--cpus=0.5','--user',f'{uid}:{uid}','--mount',f'type=bind,src={path},dst=/grant.sock,readonly','--entrypoint','/usr/local/bin/python3',IMAGE,'-I','-B','-c',CLIENT,str(uid),mode],30)
 require(p.returncode==0,'create failed or unknown; retain intent');cid=p.stdout.decode().strip();require(len(cid)==64 and all(x in '0123456789abcdef' for x in cid),'invalid ID');save(root,'client-'+index+'-id.json',{'id':cid})
 p=cmd(DOCKER+['inspect',cid]);require(p.returncode==0,'inspect unknown');o=json.loads(p.stdout)[0];h=o['HostConfig'];mounts=o['Mounts']
 require(o['Id']==cid and o['Name']=='/'+name and o['Image']==IMAGE and (o['Config']['Labels'] or {}).get(LABEL)==token and o['State']['Status']=='created' and o['Config']['User']==f'{uid}:{uid}' and h['NetworkMode']=='none' and h['ReadonlyRootfs'] and not h['Privileged'] and set(h['CapDrop'] or [])=={'ALL'} and not h['CapAdd'] and 'no-new-privileges' in (h['SecurityOpt'] or []) and h['Memory']==128*1024*1024 and h['PidsLimit']==16 and h['NanoCpus']==500000000 and h['RestartPolicy']['Name']=='no' and o['Config']['Entrypoint']==['/usr/local/bin/python3'] and o['Config']['Cmd']==['-I','-B','-c',CLIENT,str(uid),mode] and len(mounts)==1 and mounts[0]['Source']==str(path) and mounts[0]['Destination']=='/grant.sock' and not mounts[0]['RW'],'container mismatch')
 p=cmd(DOCKER+['start','--attach',cid],30);require(p.returncode==0,'client unknown; retain ID');out=json.loads(p.stdout);guard();after=os.lstat(path);require((st.st_dev,st.st_ino)==(after.st_dev,after.st_ino),'socket changed')
 p=cmd(DOCKER+['inspect',cid]);require(p.returncode==0,'cleanup inspect unavailable');o=json.loads(p.stdout)[0];require(o['Id']==cid and o['Name']=='/'+name and (o['Config']['Labels'] or {}).get(LABEL)==token and o['State']['Status']=='exited','cleanup identity mismatch')
 p=cmd(DOCKER+['rm',cid]);require(p.returncode==0 and p.stdout.decode().strip()==cid,'cleanup unresolved');save(root,'client-'+index+'-clean.json',{'id':cid,'removed':True});return out

def main():
 require(os.getuid()==1000 and os.geteuid()==1000,'fixture UID mismatch');root=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-grant-journal-',dir='/tmp'));root.chmod(0o700)
 save(root,'fixture-intent.json',{'scope':'disposable journal and fixed root UID socket probe'})
 pg=sdk=server=gate=None;success=False;pgport=port();sdkport=port();log=None
 try:
  guard();p=cmd([PG/'bin/initdb','-D',root/'pg','-U','sfactory','-A','trust','--no-instructions'],30);require(p.returncode==0,'initdb failed')
  pglog=open(root/'pg.log','wb');pg=subprocess.Popen([PG/'bin/postgres','-D',root/'pg','-h','127.0.0.1','-p',str(pgport),'-k',str(root)],env=ENV,stdout=pglog,stderr=subprocess.STDOUT)
  for _ in range(150):
   if cmd([PG/'bin/pg_isready','-h','127.0.0.1','-p',str(pgport)]).returncode==0:break
   time.sleep(.1)
  else:raise RuntimeError('disposable postgres unavailable')
  require(cmd([PG/'bin/createdb','-h','127.0.0.1','-p',str(pgport),'-U','sfactory','sfactory_verification']).returncode==0,'createdb failed')
  sdkenv={**ENV,'SFACTORY_FIXTURE_DATABASE_URL':f'postgres://sfactory@127.0.0.1:{pgport}/sfactory_verification'}
  sdklog=open(root/'sdk.log','wb');sdk=subprocess.Popen([str(SDK),f'127.0.0.1:{sdkport}'],env=sdkenv,stdout=sdklog,stderr=subprocess.STDOUT)
  def start_restate():
   nonlocal log
   log=open(root/'restate.log','w+');p=subprocess.Popen([str(RESTATE),'--base-dir',str(root/'restate'),'--node-name','grant-fixture','--bind-ip','127.0.0.1','--use-random-ports','true','--listen-mode','tcp','--no-logo','--log-format','json'],env=ENV,stdout=log,stderr=subprocess.STDOUT)
   for _ in range(250):
    require(p.poll() is None,'restate exited');records=[]
    for line in (root/'restate.log').read_text().splitlines():
     try:records.append(json.loads(line))
     except json.JSONDecodeError:pass
    ports={r.get('span',{}).get('server_name'):r.get('span',{}).get('server.port') for r in records if 'listening' in r.get('fields',{}).get('message','').lower()}
    if ports.get('http-ingress-server') and ports.get('admin-api-server'):return p,ports['http-ingress-server'],ports['admin-api-server']
    time.sleep(.1)
   raise RuntimeError('restate startup unknown')
  server,ingress,admin=start_restate();status,_=post(f'http://127.0.0.1:{admin}/deployments',{'uri':f'http://127.0.0.1:{sdkport}'});require(status in (200,201),'fixture registration failed')
  base=f'http://127.0.0.1:{ingress}';request={'schema_version':1,'repository':'fixture','target_ref':'refs/heads/main','base_revision':'a'*40,'intent':'build fixture','acceptance_criteria':['passes fixture']}
  require(post(base+f'/restate/call/RuntimeIntakeJournal/{INTENT}/submit_and_schedule',request)[0]==200,'handoff failed')
  status,assigned=post(base+'/restate/call/WorkerQueueJournal/runtime-queue/pull',{'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','ttl_ms':300000});require(status==200 and assigned['Assigned']['work_package_id']==TASK,'claim failed')
  gate_log=open(root/'gate.log','wb');gate=subprocess.Popen([str(GATE),str(root),str(ingress)],env=ENV,stdout=gate_log,stderr=subprocess.STDOUT)
  for _ in range(100):
   if (root/'grant.sock').exists():break
   require(gate.poll() is None,'gate exited');time.sleep(.05)
  else:raise RuntimeError('gate unavailable')
  require(client(root,'wrong-uid',2001,'valid')=={'status':403},'nonroot peer accepted')
  require(client(root,'wrong-generation',0,'wrong')=={'status':403},'wrong generation accepted')
  require(client(root,'partial-wrong-uid',2001,'partial')=={'status':403},'wrong UID partial body was not promptly denied')
  lease=assigned['Assigned']['lease'];proof={'attempt':lease['attempt'],'token':lease['token']}
  require(post(base+f'/restate/call/ClaimLeaseJournal/{TASK}/renew',{'proof':proof,'ttl_ms':1000})[0]==200,'denied client unexpectedly reserved claim')
  require(client(root,'lost',0,'lost')=={'lost_ack':True},'lost acknowledgement fixture failed')
  first=client(root,'first',0,'valid');second=client(root,'repeat',0,'valid');require(first.get('status')==200 and first==second,'grant replay mismatch')
  claim=base+f'/restate/call/ClaimLeaseJournal/{TASK}';require(post(claim+'/claim',{'ttl_ms':1000,'expected_previous_attempt':1})[0]==409,'claim not fenced')
  stop(gate);gate=None;stop(server);server=None;log.close();log=None
  server,ingress,admin=start_restate();gate_log.close();gate_log=open(root/'gate2.log','wb');os.unlink(root/'grant.sock');gate=subprocess.Popen([str(GATE),str(root),str(ingress)],env=ENV,stdout=gate_log,stderr=subprocess.STDOUT)
  for _ in range(100):
   if (root/'grant.sock').exists():break
   require(gate.poll() is None,'gate exited');time.sleep(.05)
  else:raise RuntimeError('gate restart unavailable')
  require(client(root,'restart',0,'valid')==first,'restart grant changed')
  base=f'http://127.0.0.1:{ingress}';require(post(base+f'/restate/call/ClaimLeaseJournal/{TASK}/claim',{'ttl_ms':1000,'expected_previous_attempt':1})[0]==409,'restart fence lost')
  guard();save(root,'complete.json',{'result':'pass','disposable':True});success=True
  print('PASS: real journal + UID0 root gate; wrong peer/generation denied, lost ack/replay/restart fenced')
 finally:
  stop(gate);stop(server);stop(sdk);stop(pg)
  if log:log.close()
  if success:shutil.rmtree(root)
  else:print('Fixture retained for reconciliation: '+str(root),file=sys.stderr)

if __name__=='__main__':main()
