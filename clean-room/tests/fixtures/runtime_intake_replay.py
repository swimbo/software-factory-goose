#!/usr/bin/env python3
"""Disposable loopback Restate/Postgres runtime handoff test; no authentication claim."""
import concurrent.futures,json,os,pathlib,socket,subprocess,tempfile,time,urllib.error,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[2];SDK=ROOT/'target/debug/examples/runtime_intake_fixture'
NODE='/Users/bo/.local/opt/node/bin/node';PACKAGE=pathlib.Path('/Users/bo/.local/opt/node/bin/restate-server').resolve().parent.parent
SERVER=subprocess.check_output([NODE,'-p','require.resolve("@restatedev/restate-server-darwin-arm64/bin/restate-server")'],cwd=PACKAGE,text=True).strip();PG='/opt/homebrew/opt/postgresql@17/bin'
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def post(url,body):
 request=urllib.request.Request(url,data=None if body is None else json.dumps(body).encode(),headers={} if body is None else {'content-type':'application/json'},method='POST')
 try:
  with urllib.request.urlopen(request,timeout=10) as result:
   raw=result.read();return result.status,json.loads(raw) if raw else None
 except urllib.error.HTTPError as error:return error.code,None
def stop(p):
 if p and p.poll() is None:
  p.terminate()
  try:p.wait(timeout=15)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
with tempfile.TemporaryDirectory(prefix='sfactory-intake-handoff-') as tmp:
 env={'PATH':'/usr/bin:/bin','HOME':tmp,'LC_ALL':'C','RUST_LOG':'info'};pgport=port();sdkport=port();pg=None;sdk=None;server=None
 subprocess.run([PG+'/initdb','-D',tmp+'/pg','-U','sfactory','-A','trust','--no-instructions'],env=env,stdout=subprocess.DEVNULL,check=True)
 with open(tmp+'/pg.log','w') as pglog,open(tmp+'/sdk.log','w') as sdklog,open(tmp+'/restate.log','w+') as log:
  try:
   pg=subprocess.Popen([PG+'/postgres','-D',tmp+'/pg','-h','127.0.0.1','-p',str(pgport),'-k',tmp],env=env,stdout=pglog,stderr=subprocess.STDOUT)
   for _ in range(150):
    if subprocess.run([PG+'/pg_isready','-h','127.0.0.1','-p',str(pgport)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
    time.sleep(.1)
   else:raise RuntimeError('postgres unavailable')
   subprocess.run([PG+'/createdb','-h','127.0.0.1','-p',str(pgport),'-U','sfactory','sfactory_verification'],env=env,check=True)
   env['SFACTORY_FIXTURE_DATABASE_URL']=f'postgres://sfactory@127.0.0.1:{pgport}/sfactory_verification'
   sdk=subprocess.Popen([str(SDK),f'127.0.0.1:{sdkport}'],cwd=tmp,env=env,stdout=sdklog,stderr=subprocess.STDOUT)
   def start():
    log.seek(0);log.truncate();log.flush();p=subprocess.Popen([SERVER,'--base-dir',tmp+'/state','--node-name','handoff','--bind-ip','127.0.0.1','--use-random-ports','true','--listen-mode','tcp','--no-logo','--log-format','json'],cwd=tmp,env=env,stdout=log,stderr=subprocess.STDOUT)
    for _ in range(250):
     if p.poll() is not None:raise RuntimeError('Restate exited')
     records=[]
     for line in pathlib.Path(log.name).read_text().splitlines():
      try:records.append(json.loads(line))
      except json.JSONDecodeError:pass
     ports={r.get('span',{}).get('server_name'):r.get('span',{}).get('server.port') for r in records if 'listening' in r.get('fields',{}).get('message','').lower()}
     if ports.get('http-ingress-server') and ports.get('admin-api-server'):return p,ports['http-ingress-server'],ports['admin-api-server']
     time.sleep(.1)
    stop(p);raise RuntimeError('Restate unavailable')
   server,ingress,admin=start();status,_=post(f'http://127.0.0.1:{admin}/deployments',{'uri':f'http://127.0.0.1:{sdkport}'});assert status in (200,201)
   base=f'http://127.0.0.1:{ingress}';key='01ARZ3NDEKTSV4RRFFQ69G5FAZ';task='01ARZ3NDEKTSV4RRFFQ69G5FAY';path=base+f'/restate/call/RuntimeIntakeJournal/{key}/submit_and_schedule';queue=base+'/restate/call/WorkerQueueJournal/runtime-queue'
   request={'schema_version':1,'repository':'fixture','target_ref':'refs/heads/main','base_revision':'a'*40,'intent':'build fixture','acceptance_criteria':['passes fixture']}
   inspect=base+f'/restate/call/RuntimeIntakeJournal/{key}/inspect'
   assert post(inspect,None)==(200,None)
   denied=subprocess.run([str(ROOT/'target/debug/examples/runtime_intake_backend_fixture'),str(ingress),'deny'],cwd=tmp,env=env,capture_output=True,text=True,timeout=20,check=True)
   assert 'unqualified pull denied' in denied.stdout
   assert post(path,{**request,'intent':'other'})[0]==403
   assert post(inspect,None)==(200,None)
   assert post(queue+'/pull',{'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FAX','ttl_ms':300000})==(200,'Empty')
   encoded=json.dumps(request).encode()
   with socket.create_connection(('127.0.0.1',ingress),timeout=10) as wire:
    wire.sendall(f'POST /restate/call/RuntimeIntakeJournal/{key}/submit_and_schedule HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {len(encoded)}\r\n\r\n'.encode()+encoded)
    assert wire.recv(1)==b'H'
   with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:results=list(pool.map(lambda _:post(path,request),range(5)))
   assert all(code==200 and result==results[0][1] for code,result in results),results
   assert results[0][1]['schedule']['work_package_id']==task
   assert post(inspect,None)==results[0]
   assert post(path,{**request,'intent':'other'})[0]==403
   verified=subprocess.run([str(ROOT/'target/debug/examples/runtime_intake_backend_fixture'),str(ingress),'verify'],cwd=tmp,env=env,capture_output=True,text=True,timeout=20,check=True)
   assert 'published handoff' in verified.stdout
   pull={'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','ttl_ms':300000};status,assignment=post(queue+'/pull',pull);assert status==200 and assignment['Assigned']['work_package_id']==task
   assert post(queue+'/pull',pull)==(200,assignment)
   stop(server);server,ingress,admin=start();base=f'http://127.0.0.1:{ingress}'
   assert post(base+f'/restate/call/RuntimeIntakeJournal/{key}/submit_and_schedule',request)==results[0]
   assert post(base+f'/restate/call/RuntimeIntakeJournal/{key}/inspect',None)==results[0]
   assert post(base+'/restate/call/WorkerQueueJournal/runtime-queue/pull',pull)==(200,assignment)
   print('PASS: catalog-bound intake, qualification, durable queue/claim, lost acknowledgment and restart replay')
  finally:stop(server);stop(sdk);stop(pg)
