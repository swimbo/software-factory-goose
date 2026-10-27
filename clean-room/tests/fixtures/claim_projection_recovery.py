#!/usr/bin/env python3
"""Own disposable Restate + PostgreSQL only. Drops ONLY its sfactory_verification database.
No production endpoint, credentials, standing service, or real worker/model invocation.
Run after cargo build --locked -p control-plane --all-features --example claim_recovery_fixture.
"""
import json, os, pathlib, socket, subprocess, tempfile, time, urllib.error, urllib.request
ROOT = pathlib.Path(__file__).resolve().parents[2]
SDK = ROOT / 'target/debug/examples/claim_recovery_fixture'
NODE = '/Users/bo/.local/opt/node/bin/node'
PACKAGE = pathlib.Path('/Users/bo/.local/opt/node/bin/restate-server').resolve().parent.parent
PG = pathlib.Path('/opt/homebrew/opt/postgresql@17/bin')

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]
def stop(p):
    if p is not None and p.poll() is None:
        p.terminate()
        try: p.wait(timeout=15)
        except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
def post(url,body=None):
    req=urllib.request.Request(url,data=None if body is None else json.dumps(body).encode(),headers={} if body is None else {'Content-Type':'application/json'},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=10) as response:
            data=response.read(); return response.status,json.loads(data) if data else None
    except urllib.error.HTTPError as error:
        return error.code,error.read().decode(errors='replace')[:1000]
def run():
    server_binary=subprocess.check_output([NODE,'-p','require.resolve("@restatedev/restate-server-darwin-arm64/bin/restate-server")'],cwd=PACKAGE,text=True).strip()
    with tempfile.TemporaryDirectory(prefix='sfactory-claim-recovery-') as temp:
        root=pathlib.Path(temp); processes=[]; logs=[]
        env={'PATH':'/Users/bo/.local/opt/node/bin:/usr/bin:/bin','HOME':temp,'LC_ALL':'C','RUST_LOG':'info'}
        pg_port,sdk_port=port(),port()
        env['SFACTORY_FIXTURE_DATABASE_URL']=f'postgres://postgres@127.0.0.1:{pg_port}/sfactory_verification'
        def launch(args,name):
            log=open(root/name,'w'); logs.append(log)
            p=subprocess.Popen(args,cwd=temp,env=env,stdout=log,stderr=subprocess.STDOUT); processes.append(p); return p
        def pgargs(command):return [str(PG/command),'-h','127.0.0.1','-p',str(pg_port),'-U','postgres']
        def sql(query):
            return subprocess.check_output(pgargs('psql')+['-d','sfactory_verification','-v','ON_ERROR_STOP=1','-tAc',query],env=env,text=True).strip()
        def snapshot():
            return json.loads(sql("SELECT coalesce(jsonb_agg(jsonb_build_object('invocation_id',invocation_id,'step_seq',step_seq,'payload',payload) ORDER BY payload->>'work_package_id',(payload->>'version')::bigint),'[]'::jsonb) FROM outbox WHERE step_kind='claim_transition_v1'"))
        def start_sdk():
            p=launch([str(SDK),f'127.0.0.1:{sdk_port}'],f'sdk-{len(processes)}.log')
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                if p.poll() is not None: raise RuntimeError('fixture SDK exited')
                try:
                    with socket.create_connection(('127.0.0.1',sdk_port),timeout=.2):return p
                except OSError:time.sleep(.05)
            raise RuntimeError('SDK readiness timeout')
        def start_restate():
            name=f'restate-{len(processes)}.log'
            p=launch([server_binary,'--base-dir',temp+'/journal','--node-name','sfactory-claim-recovery','--bind-ip','127.0.0.1','--use-random-ports','true','--listen-mode','tcp','--no-logo','--log-format','json'],name)
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                if p.poll() is not None:raise RuntimeError('fixture Restate exited')
                records=[]
                for line in (root/name).read_text().splitlines():
                    try:records.append(json.loads(line))
                    except json.JSONDecodeError:pass
                ports={r.get('span',{}).get('server_name'):r.get('span',{}).get('server.port') for r in records if 'listening' in r.get('fields',{}).get('message','').lower()}
                if ports.get('http-ingress-server') and ports.get('admin-api-server'):
                    return p,f"http://127.0.0.1:{ports['http-ingress-server']}",ports['admin-api-server']
                time.sleep(.1)
            raise RuntimeError('Restate readiness timeout')
        try:
            subprocess.run([str(PG/'initdb'),'-D',temp+'/pg','-U','postgres','-A','trust','--no-instructions'],env=env,stdout=subprocess.DEVNULL,check=True)
            postgres=launch([str(PG/'postgres'),'-D',temp+'/pg','-h','127.0.0.1','-p',str(pg_port),'-k',temp],'postgres.log')
            deadline=time.monotonic()+15
            while subprocess.run(pgargs('pg_isready'),env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
                if postgres.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Postgres readiness failure')
                time.sleep(.1)
            subprocess.run(pgargs('createdb')+['sfactory_verification'],env=env,check=True)
            sdk=start_sdk(); server,base,admin=start_restate()
            deadline=time.monotonic()+15
            while True:
                try:code,body=post(f'http://127.0.0.1:{admin}/deployments',{'uri':f'http://127.0.0.1:{sdk_port}'});break
                except OSError:
                    if time.monotonic()>deadline:raise
                    time.sleep(.1)
            assert code in (200,201),(code,body)
            def call(handler,body=None,key='recovery-task'):
                return post(base+f'/restate/call/ClaimLeaseJournal/{key}/{handler}',body)
            spec={'repository':'fixture','base_revision':'a'*40}
            assert call('initialize',spec)[0]==200
            code,lease=call('claim',{'ttl_ms':300000,'expected_previous_attempt':0});assert code==200,(code,"claim failed")
            completion={'proof':{'attempt':lease['attempt'],'token':lease['token']},'receipt':{'status':'completed','sha':'b'*40,'diff':'SQL_RECOVERY_DIFF_CANARY_MUST_BE_WITHHELD','turn_count':1,'exit_code':0,'wall_time_ms':1,'spend_usd':0.01}}
            code,state=call('complete',completion);assert code==200 and state['version']==3,(code,"completion failed")
            assert state['last_completion']['lease']['token']==lease['token']
            assert state['last_completion']['receipt']['diff']=='SQL_RECOVERY_DIFF_CANARY_MUST_BE_WITHHELD'
            original=snapshot();assert len(original)==3
            safe=json.dumps(original)
            assert lease['token'] not in safe and 'SQL_RECOVERY_DIFF_CANARY' not in safe
            assert all(r['payload']['snapshot']['schema_version']==2 for r in original)
            assert [r['payload']['version'] for r in original]==[1,2,3]
            assert len({(r['invocation_id'],r['step_seq']) for r in original})==3
            vector_version=sql("select extversion from pg_extension where extname='vector'")
            # SDK closes its pool; ONLY our freshly-created database is destroyed in full.
            stop(sdk)
            subprocess.run(pgargs('dropdb')+['sfactory_verification'],env=env,check=True)
            subprocess.run(pgargs('createdb')+['sfactory_verification'],env=env,check=True)
            assert sql("select count(*) from pg_tables where schemaname='public'")=='0'
            sdk=start_sdk()  # migrations reconstruct schema, not event data
            assert snapshot()==[] and sql('select count(*) from claim_lease_projection')=='0'
            # Total SQL loss does not erase journal authority; abrupt restart proves retention.
            server.kill();server.wait(timeout=10)
            server,base,admin=start_restate()
            assert call('status')==(200,state)
            code,report=call('reexport_claim_history');assert code==200,(code,report)
            assert report=={'work_package_id':'recovery-task','events':3,'latest_version':3,'quarantined':False},report
            assert snapshot()==original
            assert json.loads(sql("select snapshot from claim_lease_projection where work_package_id='recovery-task'"))==original[-1]['payload']['snapshot']
            assert call('reexport_claim_history')==(200,report) and snapshot()==original
            stop(server);server,base,admin=start_restate()
            assert call('reexport_claim_history')==(200,report) and snapshot()==original
            # Atomicity: conflicting final event rejects and rolls back earlier reinsertions.
            sql("delete from claim_lease_projection; delete from outbox where (payload->>'version')::int<3; update outbox set payload=jsonb_set(payload,'{snapshot,stage}','\"Failed\"'::jsonb)")
            corrupted=snapshot()
            assert call('reexport_claim_history')[0]==500
            assert snapshot()==corrupted and sql('select count(*) from claim_lease_projection')=='0'
            sql('delete from outbox')
            quarantined_report={**report,'quarantined':True}
            assert call('reexport_claim_history')==(200,quarantined_report) and snapshot()==original
            assert call('complete',completion)[0]==503  # recovery never silently clears quarantine
            # Known-object retention cap: no silent eviction or state mutation on rejection.
            assert call('initialize',spec,key='retention-cap')[0]==200
            code,lease=call('claim',{'ttl_ms':10000,'expected_previous_attempt':0},key='retention-cap');assert code==200
            proof={'attempt':lease['attempt'],'token':lease['token']}
            for i in range(126):
                code,result=call('renew',{'proof':proof,'ttl_ms':100000+i},key='retention-cap');assert code==200,(i,code,"renewal failed")
            code,capped=call('status',key='retention-cap');assert code==200 and capped['version']==128,(code,"retention version mismatch")
            assert call('renew',{'proof':proof,'ttl_ms':200000},key='retention-cap')[0]==409
            assert call('status',key='retention-cap')==(200,capped)
            assert sql("select count(*) from outbox where payload->>'work_package_id'='retention-cap'")=='128'
            stop(sdk)
            subprocess.run(pgargs('dropdb')+['sfactory_verification'],env=env,check=True)
            subprocess.run(pgargs('createdb')+['sfactory_verification'],env=env,check=True)
            projection_env={**env,'SFACTORY_TEST_DATABASE_URL':env['SFACTORY_FIXTURE_DATABASE_URL']}
            subprocess.run([str(ROOT/'target/debug/examples/verify_projection')],env=projection_env,stdout=subprocess.DEVNULL,check=True)
            print(json.dumps({'result':'PASS','database_loss':'dropped/recreated owned sfactory_verification database','pgvector':vector_version,'original_event_count':3,'original_ids_preserved':True,'reexports_across_restarts':3,'terminal_conflict_rollback':True,'retention_cap':128,'production_authentication':False,'sql_safe_schema':2,'claim_capabilities_and_raw_text_absent':True,'receipt_diff_stderr_canaries_absent':True},sort_keys=True))
        finally:
            for p in reversed(processes):stop(p)
            for log in logs:log.close()
if __name__=='__main__':run()
