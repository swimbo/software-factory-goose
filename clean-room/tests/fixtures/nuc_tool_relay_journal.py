#!/usr/bin/env python3
"""Task-owned NUC relay plus disposable journal; never touches existing deployments."""
import contextlib, json, os, pathlib, socket, subprocess, tempfile, time, urllib.request
from nuc_trusted_tool_relay import post
ROOT=pathlib.Path('/tmp/sfactory-tool-relay-code.f6O9xEoS')
SERVER=pathlib.Path('/tmp/sfactory-gate-linux.X4ZjF1LB/restate-server')
SDK=ROOT/'restate_replay_fixture'

def stop(p):
    if p and p.poll() is None:
        p.terminate()
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)

def main():
    assert os.getuid()==1000 and SDK.is_file() and SERVER.is_file()
    configured=os.environ.get('SFACTORY_JOURNAL_ROOT')
    scope=contextlib.nullcontext(configured) if configured else tempfile.TemporaryDirectory(prefix='journal-',dir=ROOT)
    with scope as tmp:
        root=pathlib.Path(tmp)
        if configured and (root.is_symlink() or not root.is_dir() or root.stat().st_uid!=os.getuid() or (root.stat().st_mode & 0o777)!=0o700):raise RuntimeError('invalid journal root')
        (root/'state').mkdir()
        s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
        env={'PATH':'/usr/bin:/bin','HOME':str(root),'RUST_LOG':'info'}
        sdk=None;server=None
        try:
            with open(root/'sdk.log','w') as sdklog,open(root/'server.log','w+') as serverlog:
                sdk=subprocess.Popen([str(SDK),'127.0.0.1:'+str(port)],env=env,cwd=root,stdout=sdklog,stderr=subprocess.STDOUT)
                server=subprocess.Popen([str(SERVER),'--base-dir',str(root/'state'),'--node-name','sfactory-relay-fixture','--bind-ip','127.0.0.1','--use-random-ports','true','--listen-mode','tcp','--no-logo','--log-format','json'],env=env,cwd=root,stdout=serverlog,stderr=subprocess.STDOUT)
                deadline=time.monotonic()+40;ports={}
                while time.monotonic()<deadline:
                    if sdk.poll() is not None or server.poll() is not None:raise RuntimeError('fixture process exited')
                    for line in (root/'server.log').read_text().splitlines():
                        try:
                            record=json.loads(line);span=record.get('span',{})
                            if 'listening' in record.get('fields',{}).get('message','').lower():ports[span.get('server_name')]=span.get('server.port')
                        except json.JSONDecodeError:pass
                    if ports.get('http-ingress-server') and ports.get('admin-api-server'):break
                    time.sleep(.1)
                else:raise RuntimeError('journal readiness timeout')
                request=urllib.request.Request('http://127.0.0.1:%s/deployments'%ports['admin-api-server'],data=json.dumps({'uri':'http://127.0.0.1:%s'%port}).encode(),headers={'content-type':'application/json'},method='POST')
                with urllib.request.urlopen(request,timeout=10) as response:assert response.status in (200,201)
                base='http://127.0.0.1:%s/restate/call/ConversationFixture/nuc-relay'%ports['http-ingress-server']
                driver='nuc_goose_relay_batch.py' if os.environ.get('SFACTORY_FIXTURE_GOOSE_BATCH')=='1' else 'nuc_trusted_tool_relay.py'
                subprocess.run(['python3',str(ROOT/driver)],env={**env,'SFACTORY_FIXTURE_JOURNAL':base,'PYTHONDONTWRITEBYTECODE':'1',**{k:os.environ[k] for k in ('SFACTORY_BATCH_ROOT','SFACTORY_FIXTURE_HOLD','SFACTORY_TASK_PROMPT','SFACTORY_CAPTURE_INITIAL','SFACTORY_FENCE_PREFLIGHT') if k in os.environ}},cwd=ROOT,timeout=90,check=True)
                print('PASS: NUC disposable journal with service-captured isolated tool response',flush=True)
        finally:stop(server);stop(sdk)

if __name__=='__main__':main()
