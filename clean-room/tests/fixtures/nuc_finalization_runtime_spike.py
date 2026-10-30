#!/usr/bin/env python3
"""Disposable loopback-only finalization integration; never connects to live services."""
import concurrent.futures,hashlib,http.client,importlib.util,json,os,pathlib,shutil,socket,subprocess,sys,tempfile,time,urllib.error,urllib.request
PG=pathlib.Path('/usr/local/libexec/software-factory-goose/postgresql17');ROOT=pathlib.Path('/tmp/sfactory-finalization-fixture.lTSmLHXN');SDK=ROOT/'target/debug/examples/finalization_runtime_fixture';OLD=ROOT/'target/debug/examples/four_catalog_upgrade_fixture';RESTATE=pathlib.Path('/usr/local/libexec/software-factory-goose/private-restate')
ENV={'PATH':'/usr/bin:/bin','HOME':'/tmp','LANG':'C','LD_LIBRARY_PATH':str(PG/'lib')};TASK='01ARZ3NDEKTSV4RRFFQ69G5FAM';INTENT='01ARZ3NDEKTSV4RRFFQ69G5FAN';OLDTASK='01ARZ3NDEKTSV4RRFFQ69G5FAR';OLDINTENT='01ARZ3NDEKTSV4RRFFQ69G5FAQ'
def require(x,msg):
 if not x:raise RuntimeError(msg)
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def cmd(args,timeout=30):
 p=subprocess.run(list(map(str,args)),env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False);require(len(p.stdout)<=65536 and len(p.stderr)<=65536,'output bound');return p
def post(url,value):
 q=urllib.request.Request(url,data=None if value is None else json.dumps(value).encode(),headers={} if value is None else {'content-type':'application/json','accept':'application/json'},method='POST')
 try:
  with urllib.request.urlopen(q,timeout=12) as r:
   b=r.read(262145);require(len(b)<=262144,'response bound');return r.status,json.loads(b) if b else None
 except urllib.error.HTTPError as e:return e.code,None
def stop(p):
 if p and p.poll() is None:
  p.terminate()
  try:p.wait(timeout=15)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
def raw(o):return json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def grant_request(grant,mode):
 g=grant['generation'];recipe={'schema':1,'purpose':'nuc-goose-write-files-v1','generation':g,'task_id':TASK,'worker_uid':2001,'goose_binary_sha256':'802d1478e6a53ef7c68a56ccfed3aec59eab0afd68aa411ec0c1b516dc5334db','worker_image_id':'sha256:509d7c54cfdbf6afd9e1c80ff924d367bdaf0979e6ef63b1f7d1134ce3a9710a','worker_program_sha256':'c0f51ee7767c6448c1fa3908e137c280753de302af9e7196751bb67fbc601df1','writer_image_id':'sha256:2efe778192492f6934540be9771bc1057b4724fe20bed6f71a362a4b91636b48','writer_program_sha256':'4ade60e556a391795b8f2b13a5e6d52efb68a04d6d806f5e0bf76e3cdc0d3d8c','profile_sha256':'a'*64,'prompt_sha256':'b'*64,'relay_scope_template_sha256':'c'*64,'provider_binding_sha256':'d'*64,'fixed_parent':'sfactory'+g.lower()+'.slice'}
 cat={'schema':1,'scope':grant['scope'],'boot_id':'synthetic-boot','cgroup_dev':29,'cgroup_ino':42,'recipe_sha256':sha(raw(recipe)),'max_expiry_ms':grant['hard_deadline_ms']};gb=raw(grant);cb=raw(cat);binding=sha(b'sfactory-root-grant-v1\0'+len(gb).to_bytes(8,'big')+gb+len(cb).to_bytes(8,'big')+cb)
 snapshot={'files':{'hello.py':'1'*64,'test_hello.py':'2'*64}}
 evaluation={'evaluator_id':'synthetic-evaluator','receipt_sha256':'3'*64,'snapshot_sha256':sha(raw(snapshot))}
 cleanup={'boot_id':'synthetic-boot','cgroup_dev':29,'cgroup_ino':42,'writer_id':'4'*64,'goose_id':'5'*64,'closure_sha256':'6'*64,'observation_sha256':'7'*64,'reconciliation_sha256':'8'*64,'terminal_receipts_sha256':'9'*64}
 if mode=='pass':evidence={'kind':'evaluated_pass','snapshot':snapshot,'evaluation':evaluation,'commit':{'revision':'a'*40,'blobs':snapshot['files']},'cleanup':cleanup}
 elif mode=='fail':evidence={'kind':'evaluated_fail','snapshot':snapshot,'evaluation':evaluation,'commit':None,'cleanup':cleanup}
 else:evidence={'kind':'unknown','phase':'launch','reason':'outcome_unknown','observation_sha256':'e'*64}
 return {'schema':1,'reservation':grant,'catalog':cat,'recipe':recipe,'binding_sha256':binding,'evidence':evidence,'spend':'unknown'}
def main():
 mode=sys.argv[1] if len(sys.argv)==2 else 'unknown';require(mode in ('unknown','pass','fail'),'invalid fixed fixture variant')
 require(os.getuid()==1000 and all(p.is_file() for p in (SDK,OLD,RESTATE,PG/'bin/postgres')),'fixture binaries unavailable');require(sha(RESTATE.read_bytes())=='a45eba5044e331636b9da5a8f37fc901dec4cd3ccfcb10889241f76fe9c209db','restate binary mismatch');root=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-finalization-run-',dir='/tmp'));root.chmod(0o700);pg=srv=old=new=None;logs=[];success=False
 def log(name):
  f=open(root/name,'ab');logs.append(f);return f
 def wait_port(p,n):
  for _ in range(150):
   require(p.poll() is None,'owned process exited')
   try:
    with socket.create_connection(('127.0.0.1',n),timeout=.1):return
   except OSError:time.sleep(.1)
  raise RuntimeError('fixture port unavailable')
 try:
  pgport=port();require(cmd([PG/'bin/initdb','-D',root/'pg','-U','sfactory','-A','trust','--no-instructions']).returncode==0,'initdb failed');pg=subprocess.Popen([str(PG/'bin/postgres'),'-D',str(root/'pg'),'-h','127.0.0.1','-p',str(pgport),'-k',str(root)],env=ENV,stdout=log('postgres.log'),stderr=subprocess.STDOUT);wait_port(pg,pgport)
  require(cmd([PG/'bin/createdb','-h','127.0.0.1','-p',str(pgport),'-U','sfactory','sfactory_verification']).returncode==0,'createdb failed')
  env={**ENV,'SFACTORY_FIXTURE_DATABASE_URL':f'postgres://sfactory@127.0.0.1:{pgport}/sfactory_verification'};oldport=port();old=subprocess.Popen([str(OLD),f'127.0.0.1:{oldport}'],env=env,stdout=log('old.log'),stderr=subprocess.STDOUT);wait_port(old,oldport)
  def start_restate():
   rp=root/'restate.log';rl=open(rp,'wb');logs.append(rl)
   proc=subprocess.Popen([str(RESTATE),'--base-dir',str(root/'restate'),'--node-name','finalization-fixture','--bind-ip','127.0.0.1','--use-random-ports','true','--listen-mode','tcp','--no-logo','--log-format','json'],env=ENV,stdout=rl,stderr=subprocess.STDOUT)
   for _ in range(250):
    require(proc.poll() is None,'restate exited');records=[]
    for line in rp.read_text().splitlines():
     try:records.append(json.loads(line))
     except json.JSONDecodeError:pass
    ports={r.get('span',{}).get('server_name'):r.get('span',{}).get('server.port') for r in records if 'listening' in r.get('fields',{}).get('message','').lower()}
    if ports.get('http-ingress-server') and ports.get('admin-api-server'):return proc,ports
    time.sleep(.1)
   raise RuntimeError('restate ports unavailable')
  srv,ports=start_restate()
  ingress,admin=ports['http-ingress-server'],ports['admin-api-server'];base=f'http://127.0.0.1:{ingress}';registration_status,registration=post(f'http://127.0.0.1:{admin}/deployments',{'uri':f'http://127.0.0.1:{oldport}'});require(registration_status in (200,201) and isinstance(registration.get('id'),str),'old registration failed')
  oldpath=base+f'/restate/call/ClaimLeaseJournal/{OLDTASK}';spec={'repository':'fixture','base_revision':'a'*40};require(post(oldpath+'/initialize',spec)[0]==200,'old claim setup failed')
  qs,qv=post(f'http://127.0.0.1:{admin}/query',{'query':"SELECT key, value_utf8 FROM state WHERE service_name = 'ClaimLeaseJournal' AND service_key = '"+OLDTASK+"' ORDER BY key"});require(qs==200 and isinstance(qv,dict) and isinstance(qv.get('rows'),list),'fixed state query unavailable');print('QUERY_SHAPE',sorted(qv),sorted(qv['rows'][0]) if qv['rows'] else [],flush=True)
  mod=importlib.util.spec_from_file_location('fixed_replay_probe',ROOT/'nuc_registry_replay_probe.py');probe=importlib.util.module_from_spec(mod);mod.loader.exec_module(probe);probe.ADMIN_PORT=admin;meta=json.load(urllib.request.urlopen(f'http://127.0.0.1:{admin}/deployments/'+registration['id'],timeout=5));print('METADATA_SHAPE',sorted(meta),type(meta.get('uri')).__name__,type(meta.get('endpoint')).__name__,flush=True);require(len(probe.deployment(registration['id'],f'http://127.0.0.1:{oldport}'))==64,'deployment metadata unavailable');prior=probe.query('ClaimLeaseJournal',OLDTASK);require(any(x['key']=='claim' for x in prior),'prior claim digest missing')
  newport=port();new=subprocess.Popen([str(SDK),f'127.0.0.1:{newport}'],env=env,stdout=log('new.log'),stderr=subprocess.STDOUT);wait_port(new,newport);require(post(f'http://127.0.0.1:{admin}/deployments',{'uri':f'http://127.0.0.1:{newport}'})[0]==201,'new registration failed')
  require(post(oldpath+'/initialize',spec)[0]==200,'old history unreadable');claim=base+f'/restate/call/ClaimLeaseJournal/{TASK}';require(post(claim+'/initialize',spec)[0]==200,'initialize failed');status,lease=post(claim+'/claim',{'ttl_ms':6000,'expected_previous_attempt':0});require(status==200,'claim failed');status,grant=post(claim+'/reserve_current_launch',None);require(status==200,'reservation failed');request=grant_request(grant,mode)
  while int(time.time()*1000)<=grant['expires_at_ms']+100:time.sleep(.1)
  # Send and close without reading; the following replay retrieves the durable result.
  data=raw(request);c=socket.create_connection(('127.0.0.1',ingress),timeout=5);c.sendall((f'POST /restate/call/ClaimLeaseJournal/{TASK}/finalize_root HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n').encode()+data);require(c.recv(1)==b'H','lost-ACK response unavailable');c.close()
  with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:responses=list(ex.map(lambda _:post(claim+'/finalize_root',request),range(3)))
  require(all(s==200 and v==responses[0][1] for s,v in responses),'identical replay changed');first=responses[0][1];require(first['export']=='pending' and first['record']['spend']=='unknown','pending state invalid')
  changed=json.loads(json.dumps(request));changed['evidence']['observation_sha256' if mode=='unknown' else 'evaluation'] = 'f'*64 if mode=='unknown' else {**changed['evidence']['evaluation'],'receipt_sha256':'f'*64};require(post(claim+'/finalize_root',changed)[0]==409,'changed replay accepted')
  for name,body in [('initialize',spec),('claim',{'ttl_ms':1000,'expected_previous_attempt':1}),('renew',{'proof':{'attempt':lease['attempt'],'token':lease['token']},'ttl_ms':1000}),('complete',{'proof':{'attempt':lease['attempt'],'token':lease['token']},'receipt':{'status':'failed','exit_code':1,'stderr_tail':'fixture'}})]:require(post(claim+'/'+name,body)[0]==409,'worker fence failed: '+name)
  status,view=post(claim+'/root_finalization_status',None);require(status==200 and view['legacy_claim_is_historical'] and 'token' not in json.dumps(view['legacy_claim']) and view['finalization']['record']['spend']=='unknown','status unsafe')
  status,export=post(claim+'/reexport_root_finalization',None);require(status==200 and export['export']=='current','export not current')
  def sql(query):
   p=cmd([PG/'bin/psql','-h','127.0.0.1','-p',str(pgport),'-U','sfactory','-d','sfactory_verification','-v','ON_ERROR_STOP=1','-Atc',query]);require(p.returncode==0,'fixture SQL failed');return p.stdout.decode().strip()
  require(sql('DELETE FROM root_finalization_projection;')=='DELETE 1','fixture row missing');require(post(claim+'/reexport_root_finalization',None)[1]['export']=='current','reexport failed');require(sql('SELECT count(*) FROM root_finalization_projection;')=='1','reexport did not restore')
  sql("UPDATE root_finalization_projection SET payload_sha256='"+'f'*64+"';");require(post(claim+'/reexport_root_finalization',None)[1]['export']=='quarantined','conflict not quarantined');require(post(claim+'/reexport_root_finalization',None)[1]['export']=='quarantined','quarantine cleared');reserved_before=probe.query('ClaimLeaseJournal',TASK);require({'claim','launch_reservation_v1','root_finalization_v1'}.issubset({v['key'] for v in reserved_before}),'permanent reservation state missing')
  stop(new);new=None;stop(srv);srv=None;srv,ports=start_restate();ingress=ports['http-ingress-server'];base=f'http://127.0.0.1:{ingress}';claim=base+f'/restate/call/ClaimLeaseJournal/{TASK}';oldpath=base+f'/restate/call/ClaimLeaseJournal/{OLDTASK}';new=subprocess.Popen([str(SDK),f'127.0.0.1:{newport}'],env=env,stdout=log('new-restart.log'),stderr=subprocess.STDOUT);wait_port(new,newport);status,replayed=post(claim+'/finalize_root',request);require(status==200 and replayed['export']=='quarantined','restart replay changed');require(post(oldpath+'/initialize',spec)[0]==200,'old history lost');probe.ADMIN_PORT=ports['admin-api-server'];require(probe.query('ClaimLeaseJournal',OLDTASK)==prior,'prior state digest changed');require(probe.query('ClaimLeaseJournal',TASK)==reserved_before,'reserved history changed')
  success=True;print('PASS '+mode+': expired reservation, concurrent/lost-ack replay, worker fence, sanitized status, reexport, conflict quarantine and Restate/SDK restart; synthetic direct ingress only')
 finally:
  for p in (new,old,srv,pg):stop(p)
  for f in logs:f.close()
  if success:shutil.rmtree(root)
  else:print('Retained fixture: '+str(root),file=sys.stderr)
if __name__=='__main__':main()
