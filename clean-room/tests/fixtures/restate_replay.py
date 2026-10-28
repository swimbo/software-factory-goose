#!/usr/bin/env python3
"""Disposable same-host Restate journal fixture; not an authenticated deployment test."""
import concurrent.futures, json, os, pathlib, socket, subprocess, tempfile, time, urllib.error, urllib.request
from worker_backend_proxy import verify_worker_backend, verify_promotion_decision, prepare_promotion_execution, verify_promotion_execution
from trusted_inference_launcher_fixture import exercise as exercise_inference_launcher, verify_after_restart as verify_inference_launcher

ROOT = pathlib.Path(__file__).resolve().parents[2]
SERVER = '/Users/bo/.local/opt/node/bin/restate-server'
SDK = ROOT / 'target/debug/examples/restate_replay_fixture'
PACKAGE = pathlib.Path(SERVER).resolve().parent.parent
SERVER_BINARY = subprocess.check_output(['/Users/bo/.local/opt/node/bin/node','-p','require.resolve("@restatedev/restate-server-darwin-arm64/bin/restate-server")'], cwd=PACKAGE, text=True).strip()

def post(url, body):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), headers={} if body is None else {'content-type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors='replace')[:1000]

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def terminate(p):
    if p.poll() is None:
        p.terminate()
        try: p.wait(timeout=15)
        except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)

with tempfile.TemporaryDirectory(prefix='sfactory-restate-replay-') as tmp:
    env = {'PATH':'/Users/bo/.local/opt/node/bin:/usr/bin:/bin', 'HOME':tmp, 'RUST_LOG':'info'}
    promotion_fixture = prepare_promotion_execution(tmp, env)
    pg_bin = '/opt/homebrew/opt/postgresql@17/bin'
    pg_port = port()
    pg_env = {**env, 'LC_ALL':'C'}
    subprocess.run([pg_bin+'/initdb','-D',tmp+'/pg','-U','sfactory','-A','trust','--no-instructions'],env=pg_env,stdout=subprocess.DEVNULL,check=True)
    pglog = open(tmp+'/pg.log','w')
    postgres = subprocess.Popen([pg_bin+'/postgres','-D',tmp+'/pg','-h','127.0.0.1','-p',str(pg_port),'-k',tmp],env=pg_env,stdout=pglog,stderr=subprocess.STDOUT)
    try:
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if postgres.poll() is not None: raise RuntimeError('fixture Postgres exited')
            ready=subprocess.run([pg_bin+'/pg_isready','-h','127.0.0.1','-p',str(pg_port)],env=pg_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if ready.returncode==0: break
            time.sleep(.1)
        else:
            raise RuntimeError('fixture Postgres readiness timeout')
        subprocess.run([pg_bin+'/createdb','-h','127.0.0.1','-p',str(pg_port),'-U','sfactory','sfactory_verification'],env=pg_env,check=True)
    except BaseException:
        terminate(postgres);pglog.close();raise
    env['SFACTORY_FIXTURE_DATABASE_URL']=f'postgres://sfactory@127.0.0.1:{pg_port}/sfactory_verification'
    sdk_port = port()
    with open(os.path.join(tmp,'sdk.log'),'w') as sdklog, open(os.path.join(tmp,'server.log'),'w+') as log:
        try:
            sdk = subprocess.Popen([str(SDK),f'127.0.0.1:{sdk_port}'],cwd=tmp,env=env,stdout=sdklog,stderr=subprocess.STDOUT)
        except BaseException:
            terminate(postgres);pglog.close();raise
        server = None
        def start_server():
            log.seek(0); log.truncate(); log.flush()
            p=subprocess.Popen([SERVER_BINARY,'--base-dir',tmp+'/state','--node-name','sfactory-replay','--bind-ip','127.0.0.1','--use-random-ports','true','--listen-mode','tcp','--no-logo','--log-format','json'],cwd=tmp,env=env,stdout=log,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+25
            while time.monotonic()<deadline:
                if p.poll() is not None: raise RuntimeError('fixture Restate exited')
                with open(log.name) as read:
                    records=[]
                    for line in read:
                        try: records.append(json.loads(line))
                        except json.JSONDecodeError: pass
                ports={r.get('span',{}).get('server_name'): r.get('span',{}).get('server.port') for r in records if 'listening' in r.get('fields',{}).get('message','').lower()}
                if ports.get('http-ingress-server') and ports.get('admin-api-server'):
                    return p, ports['http-ingress-server'], ports['admin-api-server']
                time.sleep(.1)
            terminate(p); raise RuntimeError('fixture Restate readiness timeout')
        try:
            server, ingress, admin = start_server()
            deadline=time.monotonic()+10
            while True:
                try: status, result=post(f'http://127.0.0.1:{admin}/deployments',{'uri':f'http://127.0.0.1:{sdk_port}'}); break
                except (OSError, urllib.error.URLError):
                    if time.monotonic()>deadline: raise
                    time.sleep(.1)
            assert status in (200,201), (status,result)
            base=f'http://127.0.0.1:{ingress}'
            intake_key='01ARZ3NDEKTSV4RRFFQ69G5FAZ'
            intake_path=f'/restate/call/IntakeJournal/{intake_key}'
            intake={'schema_version':1,'repository':'fixture','target_ref':'refs/heads/main','base_revision':'a'*40,'intent':'build fixture','acceptance_criteria':['passes fixture']}
            conflicting={**intake,'intent':'different fixture'}
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                submissions=list(pool.map(lambda _:post(base+intake_path+'/submit',intake),range(10)))
            assert all(code==200 and value==submissions[0][1] for code,value in submissions),submissions
            admitted=submissions[0][1]
            assert admitted['request']==intake and admitted['idempotency_key']==intake_key and admitted['submitted_by']=='fixture-submitter' and admitted['created_at_ms']>0,admitted
            assert post(base+intake_path+'/submit',conflicting)[0]==409
            assert post(base+intake_path+'/inspect',None)==(200,admitted)
            race_path='/restate/call/IntakeJournal/01ARZ3NDEKTSV4RRFFQ69G5FB0'
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                race=list(pool.map(lambda request:post(base+race_path+'/submit',request),[intake,conflicting]))
            assert sorted(code for code,_ in race)==[200,409],race
            race_record=next(value for code,value in race if code==200)
            assert race_record['request'] in (intake,conflicting)
            assert post(base+race_path+'/inspect',None)==(200,race_record)
            assert post(base+'/restate/call/BudgetCounter/fixture/try_spend_microusd',200000)==(200,True)
            assert post(base+'/restate/call/BudgetCounter/fixture/try_spend_microusd',600000)==(200,False)
            assert post(base+'/restate/call/BudgetCounter/fixture/try_spend',0.01)==(200,False)
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                results=list(pool.map(lambda _:post(base+'/restate/call/BudgetCounter/race/try_spend_microusd',100000),range(10)))
            assert results.count((200,True))==7 and results.count((200,False))==3,results
            gateway_fixture = ROOT / 'target/debug/examples/gateway_restate_fixture'
            gateway_result = subprocess.run([str(gateway_fixture), base, 'exercise'], cwd=tmp, env=env, capture_output=True, text=True, timeout=30, check=True)
            assert 'PASS gateway exercised real Restate' in gateway_result.stdout
            idem = base+'/restate/call/IdempotentBudgetCounter/idem-unit/reserve'
            idem_request={'reservation_id':'01ARZ3NDEKTSV4RRFFQ69G5FAV','amount_microusd':250000}
            encoded=json.dumps(idem_request).encode()
            with socket.create_connection(('127.0.0.1',ingress),timeout=5) as wire:
                wire.sendall(b'POST /restate/call/IdempotentBudgetCounter/idem-unit/reserve HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(encoded)).encode()+b'\r\n\r\n'+encoded)
                assert wire.recv(1)==b'H'  # Response started; discard the remainder.
            assert post(idem,idem_request)==(200,True)
            assert post(idem,{**idem_request,'amount_microusd':1})[0]==409
            idem_rest={'reservation_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','amount_microusd':500000}
            idem_denied={'reservation_id':'01ARZ3NDEKTSV4RRFFQ69G5FAX','amount_microusd':1}
            assert post(idem,idem_rest)==(200,True)  # proves lost-ack retry reserved only once
            assert post(idem,idem_denied)==(200,False)
            assert post(idem,idem_denied)==(200,False)
            idem_race=base+'/restate/call/IdempotentBudgetCounter/idem-race/reserve'
            race_request={'reservation_id':'01ARZ3NDEKTSV4RRFFQ69G5FAY','amount_microusd':100000}
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                race=list(pool.map(lambda _:post(idem_race,race_request),range(10)))
            assert race.count((200,True))==10,race
            assert post(idem_race,{'reservation_id':'01ARZ3NDEKTSV4RRFFQ69G5FAZ','amount_microusd':650000})==(200,True)
            assert post(idem_race,{'reservation_id':'01ARZ3NDEKTSV4RRFFQ69G5FB0','amount_microusd':1})==(200,False)
            inference=base+'/restate/call/InferenceAuthority/inference-unit'
            infer_request={'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAV','request_digest':'a'*64,'review_digest':'b'*64,'model':'fixture-model','attempt':1,'amount_microusd':250000}
            assert post(inference+'/prepare',infer_request)==(200,'Reserved')
            assert post(inference+'/prepare',infer_request)==(200,'Reserved')
            for changed in ({**infer_request,'request_digest':'c'*64},{**infer_request,'review_digest':'d'*64},{**infer_request,'attempt':2},{**infer_request,'model':'other'},{**infer_request,'amount_microusd':1}):
                assert post(inference+'/prepare',changed)[0]==409
            encoded=json.dumps(infer_request).encode()
            with socket.create_connection(('127.0.0.1',ingress),timeout=5) as wire:
                wire.sendall(b'POST /restate/call/InferenceAuthority/inference-unit/begin HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(encoded)).encode()+b'\r\n\r\n'+encoded)
                assert wire.recv(1)==b'H'  # begin response started, then acknowledgement is discarded
            assert post(inference+'/begin',infer_request)[0]==409
            assert post(inference+'/prepare',infer_request)==(200,'DispatchingUnknown')
            pending_request={**infer_request,'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW'}
            assert post(inference+'/prepare',pending_request)==(200,'Reserved')
            final_request={**infer_request,'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAX'}
            denied_request={**infer_request,'call_id':'01ARZ3NDEKTSV4RRFFQ69G5FAY','amount_microusd':1}
            assert post(inference+'/prepare',final_request)==(200,'Reserved')
            assert post(inference+'/prepare',denied_request)==(200,'Denied')
            assert post(inference+'/begin',denied_request)[0]==409
            race_inference=base+'/restate/call/InferenceAuthority/inference-race'
            assert post(race_inference+'/prepare',infer_request)==(200,'Reserved')
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                begins=list(pool.map(lambda _:post(race_inference+'/begin',infer_request),range(10)))
            assert sorted(code for code,_ in begins)==[200]+[409]*9,begins
            launcher_ids=exercise_inference_launcher(base,env)
            queue=base+'/restate/call/WorkerQueueJournal/fixture-queue'
            task={'work_package_id':'fixture-task','spec':{'repository':'fixture','base_revision':'a'*40}}
            for invalid_key in ('.', '..', '%2e', 'a/b', 'a\\b', 'a?b', 'a#b'):
                assert post(queue+'/schedule',{**task,'work_package_id':invalid_key})[0]==400
            assert post(queue+'/schedule',task)[0]==200
            assert post(queue+'/schedule',task)[0]==200
            request={'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FAW','ttl_ms':300000}
            status,pull=post(queue+'/pull',request)
            assert status==200 and pull['Assigned']['work_package_id']=='fixture-task',(status,pull)
            assert post(queue+'/pull',request)==(200,pull)
            lease=pull['Assigned']['lease']
            completion={'request_id':request['request_id'],'proof':{'attempt':lease['attempt'],'token':lease['token']},'receipt':{'status':'failed','exit_code':1,'stderr_tail':'fixture failure'}}
            status,completed=post(queue+'/complete',completion)
            assert status==200 and completed['stage']=='CoolingDown',(status,completed)
            assert post(queue+'/complete',completion)==(200,completed)
            invalid={**completion,'proof':{**completion['proof'],'token':'01ARZ3NDEKTSV4RRFFQ69G5FAX'}}
            assert post(queue+'/complete',invalid)[0]==409
            count=subprocess.check_output([pg_bin+'/psql','-h','127.0.0.1','-p',str(pg_port),'-U','sfactory','-d','sfactory_verification','-tAc',"select count(*) from outbox where step_kind='claim_transition_v1'"],env=pg_env,text=True).strip()
            assert count=='3',count
            second={'work_package_id':'fixture-task-2','spec':task['spec']}
            assert post(queue+'/schedule',second)[0]==200
            lost={'request_id':'01ARZ3NDEKTSV4RRFFQ69G5FAY','ttl_ms':300000}
            encoded=json.dumps(lost).encode()
            with socket.create_connection(('127.0.0.1',ingress),timeout=5) as wire:
                wire.sendall(b'POST /restate/call/WorkerQueueJournal/fixture-queue/pull HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(encoded)).encode()+b'\r\n\r\n'+encoded)
                first=wire.recv(1)
                assert first == b'H', first  # HTTP response has begun, but acknowledgement is discarded.
                wire.close()
            deadline=time.monotonic()+10
            while True:
                code,claim=post(base+'/restate/call/ClaimLeaseJournal/fixture-task-2/status',None)
                if code==200 and claim and claim['stage']=='Leased': break
                if time.monotonic()>deadline: raise RuntimeError(f'lost-ack claim did not complete: {code} {claim}')
                time.sleep(.1)
            status,recovered=post(queue+'/pull',lost)
            assert status==200 and recovered['Assigned']['lease']['attempt']==1,(status,recovered)
            assert post(queue+'/pull',lost)==(200,recovered)
            nonce='01ARZ3NDEKTSV4RRFFQ69G5FAV'
            action={'operation':{'type':'promote'},'task_id':'fixture','repository':'fixture','target_ref':'refs/heads/main','candidate_sha':'a'*40,'base_sha':'b'*40,'evidence_digest':'c'*64,'reason':'fixture','audience':'fixture'}
            status,record=post(base+f'/restate/call/ApprovalJournal/{nonce}/issue',{'action':action,'ttl_ms':300000})
            assert status==200,(status,record)
            presentation={k:record[k] for k in ['action','nonce','issued_at_ms','expires_at_ms']}
            altered={**presentation,'action':{**action,'candidate_sha':'d'*40}}
            assert post(base+f'/restate/call/ApprovalJournal/{nonce}/consume',altered)[0]==409
            status,consumed=post(base+f'/restate/call/ApprovalJournal/{nonce}/consume',presentation)
            assert status==200 and consumed['consumed_at_ms'] is not None,(status,consumed)
            terminate(server);server=None
            server,ingress,admin=start_server()
            base=f'http://127.0.0.1:{ingress}'
            assert post(base+intake_path+'/submit',intake)==(200,admitted)
            assert post(base+intake_path+'/submit',conflicting)[0]==409
            assert post(base+intake_path+'/inspect',None)==(200,admitted)
            assert post(base+race_path+'/inspect',None)==(200,race_record)
            assert post(base+'/restate/call/WorkerQueueJournal/fixture-queue/pull',request)==(200,pull)
            assert post(base+'/restate/call/WorkerQueueJournal/fixture-queue/complete',completion)==(200,completed)
            assert post(base+'/restate/call/WorkerQueueJournal/fixture-queue/pull',lost)==(200,recovered)
            assert post(base+'/restate/call/BudgetCounter/fixture/try_spend_microusd',550000)==(200,True)
            assert post(base+'/restate/call/BudgetCounter/fixture/try_spend_microusd',1)==(200,False)
            gateway_result = subprocess.run([str(gateway_fixture), base, 'verify'], cwd=tmp, env=env, capture_output=True, text=True, timeout=30, check=True)
            assert 'PASS exhausted real Restate budget survives restart' in gateway_result.stdout
            assert post(base+'/restate/call/IdempotentBudgetCounter/idem-unit/reserve',idem_request)==(200,True)
            assert post(base+'/restate/call/IdempotentBudgetCounter/idem-unit/reserve',idem_denied)==(200,False)
            assert post(base+'/restate/call/InferenceAuthority/inference-unit/prepare',infer_request)==(200,'DispatchingUnknown')
            assert post(base+'/restate/call/InferenceAuthority/inference-unit/begin',infer_request)[0]==409
            verify_inference_launcher(base,launcher_ids)
            status,result=post(base+f'/restate/call/ApprovalJournal/{nonce}/consume',presentation)
            assert status==409,(status,result)
            verify_promotion_decision(ingress, env, tmp+'/promotion-decision.json', 'exercise')
            promotion_checkpoint = verify_promotion_execution(ingress, promotion_fixture, post)
            server.kill(); server.wait(timeout=10); server=None
            server,ingress,admin=start_server()
            base=f'http://127.0.0.1:{ingress}'
            gateway_result = subprocess.run([str(gateway_fixture), base, 'verify'], cwd=tmp, env=env, capture_output=True, text=True, timeout=30, check=True)
            assert 'PASS exhausted real Restate budget survives restart' in gateway_result.stdout
            assert post(base+'/restate/call/IdempotentBudgetCounter/idem-unit/reserve',idem_request)==(200,True)
            assert post(base+'/restate/call/IdempotentBudgetCounter/idem-unit/reserve',idem_denied)==(200,False)
            assert post(base+'/restate/call/InferenceAuthority/inference-unit/prepare',infer_request)==(200,'DispatchingUnknown')
            assert post(base+'/restate/call/InferenceAuthority/inference-unit/begin',infer_request)[0]==409
            verify_inference_launcher(base,launcher_ids)
            assert post(base+'/restate/call/InferenceAuthority/inference-unit/prepare',pending_request)==(200,'Reserved')
            assert post(base+'/restate/call/InferenceAuthority/inference-unit/begin',pending_request)[0]==200
            assert post(base+'/restate/call/InferenceAuthority/inference-unit/begin',pending_request)[0]==409
            assert post(base+intake_path+'/submit',intake)==(200,admitted)
            assert post(base+intake_path+'/submit',conflicting)[0]==409
            assert post(base+intake_path+'/inspect',None)==(200,admitted)
            assert post(base+race_path+'/inspect',None)==(200,race_record)
            assert post(base+'/restate/call/WorkerQueueJournal/fixture-queue/pull',request)==(200,pull)
            assert post(base+'/restate/call/WorkerQueueJournal/fixture-queue/complete',completion)==(200,completed)
            assert post(base+'/restate/call/WorkerQueueJournal/fixture-queue/pull',lost)==(200,recovered)
            assert post(base+'/restate/call/BudgetCounter/fixture/try_spend_microusd',1)==(200,False)
            status,result=post(base+f'/restate/call/ApprovalJournal/{nonce}/consume',presentation)
            assert status==409,(status,result)
            verify_promotion_decision(ingress, env, tmp+'/promotion-decision.json', 'verify')
            verify_promotion_execution(ingress, promotion_fixture, post, promotion_checkpoint)
            verify_worker_backend(ingress, env)
            print('PASS: concurrent intake retry/conflict and acknowledged budget, approval and queue pull persisted across graceful and SIGKILL restarts; real GatewayClient/Restate budget integration and exhaustion persisted; replay rejected')
        finally:
            if server is not None: terminate(server)
            terminate(sdk)
            terminate(postgres)
            pglog.close()
