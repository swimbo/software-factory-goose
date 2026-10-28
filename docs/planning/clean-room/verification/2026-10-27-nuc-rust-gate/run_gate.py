import json, os, pathlib, socket, socketserver, subprocess, tempfile, threading, time, urllib.request, select
root=pathlib.Path('/tmp/sfactory-gate-linux.X4ZjF1LB')
uid=os.geteuid(); assert uid==1000
sdk=root/'target/debug/examples/restate_replay_fixture'
test=root/'target/debug/deps/control_plane-c3bf3057853da1be'
assert sdk.is_file() and test.is_file()
def free_port():
 s=socket.socket(); s.bind(('127.0.0.1',0)); n=s.getsockname()[1]; s.close(); return n
def terminate(p):
 if p and p.poll() is None:
  p.terminate()
  try: p.wait(timeout=10)
  except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
with tempfile.TemporaryDirectory(prefix='.sfactory-nuc-gate-',dir='/home/bo') as home:
 os.chmod(home,0o700); relay=home+'/relay.sock'; gate=home+'/gate.sock'
 with open(root/'restate.log','w+') as log, open(root/'sdk.log','w+') as sdklog:
  sdkproc=server=None; thread=None
  try:
   env={'PATH':'/usr/bin:/bin','HOME':home,'RUST_LOG':'info'}
   port=free_port(); sdkproc=subprocess.Popen([str(sdk),'127.0.0.1:'+str(port)],cwd=root,env=env,stdout=sdklog,stderr=subprocess.STDOUT)
   server=subprocess.Popen([str(root/'restate-server'),'--base-dir',str(root/'state'),'--node-name','sfactory-nuc-fixture','--bind-ip','127.0.0.1','--use-random-ports','true','--listen-mode','tcp','--no-logo','--log-format','json'],cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
   deadline=time.monotonic()+35
   while time.monotonic()<deadline:
    if server.poll() is not None or sdkproc.poll() is not None: raise RuntimeError('fixture process exited')
    ports={}
    for line in (root/'restate.log').read_text().splitlines():
     try:
      record=json.loads(line)
      if 'listening' in record.get('fields',{}).get('message','').lower(): ports[record.get('span',{}).get('server_name')]=record.get('span',{}).get('server.port')
     except json.JSONDecodeError: pass
    if ports.get('http-ingress-server') and ports.get('admin-api-server'): break
    time.sleep(.1)
   else: raise RuntimeError('restate readiness timeout')
   req=urllib.request.Request('http://127.0.0.1:%s/deployments'%ports['admin-api-server'],data=json.dumps({'uri':'http://127.0.0.1:%s'%port}).encode(),headers={'content-type':'application/json'},method='POST')
   with urllib.request.urlopen(req,timeout=10) as response: assert response.status in (200,201)
   slots=threading.BoundedSemaphore(8)
   class Relay(socketserver.BaseRequestHandler):
    def handle(self):
     if not slots.acquire(blocking=False): return
     try:
      with socket.create_connection(('127.0.0.1',ports['http-ingress-server']),timeout=5) as upstream:
       self.request.settimeout(5); upstream.settimeout(5); pairs={self.request:upstream,upstream:self.request}; deadline=time.monotonic()+20; total=0
       while pairs and time.monotonic()<deadline:
        ready,_,_=select.select(list(pairs),[],[],1)
        for s in ready:
         data=s.recv(16384)
         if not data:
          pairs[s].shutdown(socket.SHUT_WR); del pairs[s]; continue
         total+=len(data)
         if total>1048576: return
         pairs[s].sendall(data)
     except (OSError,TimeoutError): pass
     finally: slots.release()
   class RelayServer(socketserver.ThreadingUnixStreamServer): daemon_threads=False
   with RelayServer(relay,Relay) as listener:
    os.chmod(relay,0o600); thread=threading.Thread(target=listener.serve_forever,kwargs={'poll_interval':0.1}); thread.start()
    try:
     testenv={**env,'SFACTORY_TEST_ATOMIC_RELAY':relay,'SFACTORY_TEST_ATOMIC_SOCKET':gate,'SFACTORY_TEST_ATOMIC_RESTATE':'http://127.0.0.1:%s'%ports['http-ingress-server']}
     subprocess.run([str(test),'atomic_peer_gate::tests::real_unix_peer_and_atomic_journal_fixture','--ignored','--exact'],env=testenv,cwd=root,timeout=90,check=True)
    finally: listener.shutdown();thread.join(timeout=5)
   print('PASS: isolated Linux kernel peer + Rust gate + loopback provider + real Restate journal')
  finally: terminate(server);terminate(sdkproc)
