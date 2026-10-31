#!/usr/bin/env python3
"""Native Linux UID/private-journal fixture. No provider, credentials or activation.

Uses only a fresh, purpose-marked NUC temporary directory and named disposable
containers. The ext4-backed chroot preserves the production socket checks; the
worker clients have separate network namespaces and only the frontend socket.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PURPOSE = "phase11a-linux-private-v1"

CONTROLLER = r"""
import http.client,http.server,json,os,pathlib,socket,socketserver,subprocess,sys,threading,time
METHODS={'initialize','admit_attempt','admit_day','revoke','reserve','begin','claim_receipts','complete'}
OWNER='fixture'
class HTTP(http.client.HTTPConnection):
 def __init__(self,path):super().__init__('localhost',timeout=10);self.path=path
 def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(10);self.sock.connect(self.path)
def post(port,path,body):
 c=http.client.HTTPConnection('127.0.0.1',port,timeout=10);c.request('POST',path,json.dumps(body),{'Content-Type':'application/json'});r=c.getresponse();raw=r.read(65537);assert len(raw)<=65536;code=r.status;c.close();return code,json.loads(raw) if raw else None
class Unix(socketserver.ThreadingMixIn,http.server.HTTPServer):
 address_family=socket.AF_UNIX;daemon_threads=True
def backend(port):
 class Handler(http.server.BaseHTTPRequestHandler):
  def log_message(self,*a):pass
  def do_POST(self):
   import struct
   uid=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
   method=self.path.rsplit('/',1)[-1]
   if uid!=2004 or self.path!='/restate/call/HarnessSpending/'+OWNER+'/'+method or method not in METHODS:self.send_error(403);return
   lengths=self.headers.get_all('Content-Length',[])
   if len(lengths)!=1 or not lengths[0].isdigit() or not 0<int(lengths[0])<=1048576:self.send_error(400);return
   body=self.rfile.read(int(lengths[0]));c=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
   c.request('POST',self.path,body,{'Content-Type':'application/json'});r=c.getresponse();raw=r.read(65537);code=r.status;c.close()
   if len(raw)>65536:self.send_error(502);return
   self.send_response(code);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 server=Unix('/private/backend/journal.sock',Handler);os.chmod('/private/backend/journal.sock',0o600);server.serve_forever()
def drop(uid,gid=2004):
 def f():os.setgroups([]);os.setgid(gid);os.setuid(uid)
 return f
def terminate(p):
 if p is not None and p.poll() is None:
  p.terminate()
  try:p.wait(timeout=8)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
def ready(path,p):
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  if p.poll() is not None:raise RuntimeError('owned process exited')
  if pathlib.Path(path).is_socket():return
  time.sleep(.05)
 raise RuntimeError('owned socket unavailable')
def main():
 for name,uid,gid,mode in [('/private',2004,2004,0o700),('/private/backend',2004,2004,0o700),('/shared',2004,3000,0o750),('/admin',0,0,0o700)]:
  pathlib.Path(name).mkdir(exist_ok=True);os.chmod(name,mode);os.chown(name,uid,gid)
 env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/private','RUST_LOG':'info','TOKIO_WORKER_THREADS':'2'}
 sdk=server=back=front=None
 def start(args,name,uid=2004,gid=2004):
  log=open('/private/'+name+'.log','ab',buffering=0)
  return subprocess.Popen(args,env=env,cwd='/private',stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,close_fds=True,preexec_fn=drop(uid,gid))
 def journal():
  log=pathlib.Path('/private/server.log');log.write_text('')
  p=start(['/opt/restate-server','--base-dir','/private/state','--node-name','harness-linux-private','--bind-ip','127.0.0.1','--use-random-ports','true','--listen-mode','tcp','--no-logo','--log-format','json'],'server')
  deadline=time.monotonic()+25
  while time.monotonic()<deadline:
   if p.poll() is not None:raise RuntimeError('owned Restate exited')
   ports={}
   for line in log.read_text().splitlines():
    try:r=json.loads(line)
    except ValueError:continue
    if 'listening' in r.get('fields',{}).get('message','').lower():s=r.get('span',{});ports[s.get('server_name')]=s.get('server.port')
   if ports.get('http-ingress-server') and ports.get('admin-api-server'):return p,ports
   time.sleep(.1)
  terminate(p);raise RuntimeError('owned Restate unavailable')
 def remove(path):
  p=pathlib.Path(path)
  if p.exists():
   if not p.is_socket():raise RuntimeError('refusing non-socket cleanup')
   p.unlink()
 def start_backend(ports):
  remove('/private/backend/journal.sock')
  p=start(['/usr/local/bin/python3','/opt/probe.py','backend',str(ports['http-ingress-server'])],'backend');ready('/private/backend/journal.sock',p);return p
 def start_frontend():
  remove('/shared/spending.sock')
  p=start(['/opt/runtime','ingress','/shared/spending.sock','/private/backend/journal.sock','2004','2000','2002','2001','fixture'],'frontend',gid=3000);ready('/shared/spending.sock',p);return p
 try:
  sdk=start(['/opt/runtime','sdk','127.0.0.1:19080'],'sdk')
  server,ports=journal()
  deadline=time.monotonic()+10
  while True:
   try:code,_=post(ports['admin-api-server'],'/deployments',{'uri':'http://127.0.0.1:19080'});assert code in(200,201);break
   except (OSError,http.client.HTTPException):
    if time.monotonic()>deadline:raise
    time.sleep(.1)
  back=start_backend(ports);front=start_frontend()
  class Admin(http.server.BaseHTTPRequestHandler):
   def log_message(self,*a):pass
   def do_POST(self):
    nonlocal server,ports,back,front
    import struct
    uid=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
    if uid!=0:self.send_error(403);return
    if self.path=='/restart-journal-backend':
     server.kill();server.wait(timeout=10);terminate(back)
     os.rename('/private/backend/journal.sock','/private/backend/retired-journal.sock')
     server,ports=journal();back=start_backend(ports)
    elif self.path=='/restart-frontend':terminate(front);front=start_frontend()
    elif self.path=='/stop':threading.Thread(target=admin.shutdown,daemon=True).start()
    else:self.send_error(404);return
    raw=json.dumps({'ok':True,'ports':ports}).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
  admin=Unix('/admin/control.sock',Admin);os.chmod('/admin/control.sock',0o600)
  print(json.dumps({'status':'ready','ports':ports,'uids':{'service':2004,'broker':2000,'collector':2002,'worker':2001,'admin':0}}),flush=True)
  admin.serve_forever()
 finally:
  for p in(front,back,server,sdk):terminate(p)
if __name__=='__main__':
 if sys.argv[1:] and sys.argv[1]=='backend':backend(int(sys.argv[2]))
 elif sys.argv[1:] and sys.argv[1]=='control':
  c=HTTP('/admin/control.sock');c.request('POST',sys.argv[2],b'{}',{'Content-Type':'application/json'});r=c.getresponse();print(r.status,r.read().decode())
 else:main()
"""

CLIENT = r"""
import http.client,json,os,socket,sys
class C(http.client.HTTPConnection):
 def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(10);self.sock.connect(sys.argv[1])
try:
 if sys.argv[2]=='tcp':
  s=socket.socket();s.settimeout(1);print(json.dumps({'uid':os.getuid(),'connect_errno':s.connect_ex(('127.0.0.1',int(sys.argv[3])))}));sys.exit(0)
 c=C('localhost',timeout=10);c.request('POST','/spending/'+sys.argv[2],sys.argv[3],{'Content-Type':'application/json','x-uid':'0','x-role':'root'});r=c.getresponse();raw=r.read(65537);assert len(raw)<=65536;print(json.dumps({'uid':os.getuid(),'status':r.status,'body':json.loads(raw) if raw and r.status==200 else None}))
except PermissionError:print(json.dumps({'uid':os.getuid(),'status':'filesystem_denied'}))
"""


def remote(host, code, data=None, timeout=60):
    completed = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            host,
            "python3",
            "-c",
            shlex.quote(code),
        ],
        input=None if data is None else json.dumps(data).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=True,
    )
    return completed.stdout.decode()


def execute(host, stage):
    if not re.fullmatch(
        r"/(?:var/)?tmp/sfactory-harness-linux-private-[a-z0-9_]+", stage
    ):
        raise ValueError("owned fixture stage required")
    source = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in (
            "crates/control-plane/src/harness_spending.rs",
            "crates/control-plane/src/harness_spending_ingress.rs",
        )
    }
    broker_sources = {
        name: (ROOT / "crates/execution/harness" / name).read_text()
        for name in (
            "protected_spending_control.py",
            "billing_capabilities.py",
            "billing_receipts.py",
            "factory_harness.py",
        )
    }
    setup = r"""
import hashlib,json,pathlib,subprocess,tarfile,os
x=json.load(__import__('sys').stdin);root=pathlib.Path(x['stage']);name=root.name;fs=root/'rootfs'
assert os.uname().machine=='x86_64', 'native amd64 fixture required'
assert root.is_dir() and root.name.startswith('sfactory-harness-linux-private-')
for path,digest in x['source'].items():
 assert hashlib.sha256((root/'project/src'/path.rsplit('/',1)[-1]).read_bytes()).hexdigest()==digest
fs.mkdir(mode=0o755);source=name+'-python-source';restate=name+'-restate-source'
def run(args):return subprocess.check_output(args,stderr=subprocess.PIPE)
try:
 run(['docker','create','--name',source,'python:3.11-slim'])
 with (root/'rootfs.tar').open('wb') as out:subprocess.run(['docker','export',source],stdout=out,check=True)
 subprocess.run(['tar','-xf',str(root/'rootfs.tar'),'--no-same-owner','-C',str(fs)],check=True)
 run(['docker','create','--name',restate,'restatedev/restate:1.8.0'])
 run(['docker','cp',restate+':/usr/local/bin/restate-server',str(root/'restate-server')])
finally:
 for n in(source,restate):subprocess.run(['docker','rm','-f',n],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
(fs/'opt').mkdir(exist_ok=True)
import shutil
shutil.copyfile(root/'target/debug/examples/runtime',fs/'opt/runtime');os.chmod(fs/'opt/runtime',0o755)
shutil.copyfile(root/'restate-server',fs/'opt/restate-server');os.chmod(fs/'opt/restate-server',0o755)
(fs/'opt/probe.py').write_text(x['controller']);(fs/'dev').mkdir(exist_ok=True)
for n in('null','urandom'):(fs/'dev'/n).touch(exist_ok=True)
clientfs=root/'broker-rootfs';clientfs.mkdir(mode=0o755)
subprocess.run(['tar','-xf',str(root/'rootfs.tar'),'--no-same-owner','-C',str(clientfs)],check=True)
(clientfs/'opt/broker').mkdir(parents=True,exist_ok=True);(clientfs/'shared').mkdir(exist_ok=True)
for module_name,data in x['broker_sources'].items():(clientfs/'opt/broker'/module_name).write_text(data)
entry="import os,subprocess; from pathlib import Path; root=Path('/fixture');\nfor p in [root]+list(root.rglob('*')):\n if not p.is_symlink() and not str(p).startswith('/fixture/dev/'):\n  os.chown(p,0,0)\nos.chmod(root,0o755);os.chroot(root);os.chdir('/');os.execv('/usr/local/bin/python3',['python3','/opt/probe.py'])"
assert name.startswith('sfactory-harness-linux-private-')
cmd=['docker','run','-d','--name',name,'--network=none','--read-only','--cap-drop=ALL','--cap-add=SYS_CHROOT','--cap-add=SETUID','--cap-add=SETGID','--cap-add=CHOWN','--cap-add=DAC_OVERRIDE','--cap-add=KILL','--security-opt=no-new-privileges','--pids-limit=512','--memory=1g','--cpus=2','--mount','type=bind,src='+str(fs)+',dst=/fixture','--mount','type=bind,src=/dev/null,dst=/fixture/dev/null,readonly','--mount','type=bind,src=/dev/urandom,dst=/fixture/dev/urandom,readonly','python:3.11-slim','python3','-c',entry]
run(cmd);print(json.dumps({'container':name,'root':str(root),'binary_sha256':hashlib.sha256((root/'target/debug/examples/runtime').read_bytes()).hexdigest()}))
"""
    metadata = json.loads(
        remote(
            host,
            setup,
            {
                "stage": stage,
                "source": source,
                "controller": CONTROLLER,
                "broker_sources": broker_sources,
            },
            timeout=60,
        )
    )
    name = metadata["container"]
    log_code = "import subprocess,json; x=json.load(__import__('sys').stdin);print(subprocess.check_output(['docker','logs',x['name']],stderr=subprocess.STDOUT).decode())"
    deadline = time.monotonic() + 45
    try:
        while time.monotonic() < deadline:
            logs = remote(host, log_code, {"name": name})
            ready = next(
                (
                    json.loads(line)
                    for line in logs.splitlines()
                    if line.startswith('{"status": "ready"')
                ),
                None,
            )
            if ready:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("native fixture startup unavailable: " + logs[-3000:])

        def client(uid, method, body, *, backend=False):
            code = """import json,subprocess,sys
x=json.load(sys.stdin);path='/backend/journal.sock' if x['backend'] else '/shared/spending.sock'
mount=x['stage']+'/rootfs/private/backend' if x['backend'] else x['stage']+'/rootfs/shared'
dest='/backend' if x['backend'] else '/shared'
cmd=['docker','run','--rm','--network=none','--read-only','--user',str(x['uid'])+':3000','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=16','--memory=64m','--mount','type=bind,src='+mount+',dst='+dest+',readonly','python:3.11-slim','python3','-c',x['client'],path,x['method'],json.dumps(x['body']) if x['method']!='tcp' else str(x['body'])]
print(subprocess.check_output(cmd,stderr=subprocess.PIPE,timeout=15).decode())
"""
            return json.loads(
                remote(
                    host,
                    code,
                    {
                        "stage": stage,
                        "uid": uid,
                        "backend": backend,
                        "method": method,
                        "body": body,
                        "client": CLIENT,
                    },
                    timeout=25,
                )
            )

        def rpc(uid, method, body):
            return client(uid, method, body)

        def protected_broker(method, body):
            program = """import json,os,sys
sys.path.insert(0,'/opt/broker')
from protected_spending_control import PrivateSpendingClient,ControlRefused
c=PrivateSpendingClient('/shared/spending.sock',service_uid=2004,broker_uid=2000,owner='fixture')
value=c(sys.argv[1],json.loads(sys.argv[2]))
try:c('initialize',{})
except ControlRefused:denied=True
else:denied=False
print(json.dumps({'uid':os.getuid(),'body':value,'admin_method_refused':denied}))
"""
            bootstrap_client = """import os,sys
os.chown('/broker',0,0);os.chmod('/broker',0o755);os.chroot('/broker');os.chdir('/')
os.setgroups([3000]);os.setgid(3000);os.setuid(2000)
os.execv('/usr/local/bin/python3',['python3','-c',sys.argv[1],sys.argv[2],sys.argv[3]])
"""
            code = """import json,subprocess,sys
x=json.load(sys.stdin)
cmd=['docker','run','--rm','--network=none','--read-only','--cap-drop=ALL','--cap-add=SYS_CHROOT','--cap-add=SETUID','--cap-add=SETGID','--cap-add=CHOWN','--security-opt=no-new-privileges','--pids-limit=16','--memory=96m','--mount','type=bind,src='+x['stage']+'/broker-rootfs,dst=/broker','--mount','type=bind,src='+x['stage']+'/rootfs/shared,dst=/broker/shared,readonly','python:3.11-slim','python3','-c',x['bootstrap'],x['program'],x['method'],json.dumps(x['body'])]
print(subprocess.check_output(cmd,stderr=subprocess.PIPE,timeout=15).decode())
"""
            reply = json.loads(
                remote(
                    host,
                    code,
                    {
                        "stage": stage,
                        "method": method,
                        "body": body,
                        "bootstrap": bootstrap_client,
                        "program": program,
                    },
                    timeout=25,
                )
            )
            assert reply["uid"] == 2000 and reply["admin_method_refused"]
            return reply["body"]

        now = time.time_ns() // 1000000
        owner = "fixture"
        opening = {task: 0 for task in ("a", "b", "c", "d", "e")}
        bootstrap = {
            "owner": owner,
            "policy_sha256": "a" * 64,
            "predecessor_fence_sha256": "b" * 64,
            "inventory_sha256": "c" * 64,
            "observed_at_ms": now,
            "approved_daily_cap_microusd": 5000000,
            "daily_cap_microusd": 5000000,
            "opening_tasks": opening,
            "opening_days": {str(now // 86400000): 3000000},
            "scopes": [],
        }
        assert rpc(2001, "initialize", bootstrap)["status"] == 403
        assert rpc(2000, "initialize", bootstrap)["status"] == 403
        assert rpc(0, "initialize", bootstrap)["status"] == 200
        scopes = {}

        def scope(task, attempt=1, amount=600000):
            issued = time.time_ns() // 1000000
            value = {
                "task": task,
                "attempt": attempt,
                "generation": task + "-" + str(attempt),
                "worker": "worker",
                "lease_sha256": "d" * 64,
                "issued_at_ms": issued,
                "expires_at_ms": issued + 300000,
                "route": {
                    "route_sha256": "e" * 64,
                    "review_sha256": "f" * 64,
                    "valid_from_ms": issued,
                    "valid_until_ms": issued + 300000,
                    "max_request_bytes": 65536,
                    "max_output_tokens": 100,
                    "components": [
                        {"id": "classifier", "max_charge_microusd": amount // 6},
                        {"id": "answer", "max_charge_microusd": amount - amount // 6},
                    ],
                },
            }
            reply = rpc(0, "admit_attempt", value)
            assert reply["status"] == 200, reply
            scopes[(task, attempt)] = reply["body"]
            return reply["body"]

        def call(task, attempt=1):
            return {
                "call_id": task + "-" + str(attempt),
                "scope_sha256": scopes[(task, attempt)],
                "request_sha256": "1" * 64,
                "sequence": 0,
                "request_bytes": 1000,
                "output_tokens": 100,
            }

        for task in opening:
            scope(task, amount=300000 if task == "e" else 600000)
        a = call("a")
        assert rpc(2001, "reserve", a)["status"] == 403
        assert rpc(2002, "reserve", a)["status"] == 403
        assert rpc(0, "reserve", a)["status"] == 403
        assert protected_broker("reserve", a) == "Reserved"
        assert rpc(2000, "reserve", a)["body"] == "Reserved"
        assert protected_broker("begin", a) is True
        assert rpc(2000, "begin", a)["status"] == 409
        assert rpc(2000, "reserve", call("b"))["body"] == "Reserved"
        assert rpc(2000, "reserve", call("c"))["body"] == "Reserved"
        assert rpc(2000, "reserve", call("d"))["body"] == "Denied"
        claim = {
            "call_id": a["call_id"],
            "request_sha256": a["request_sha256"],
            "scope_sha256": a["scope_sha256"],
            "manifest_sha256": "2" * 64,
            "generation_ids": ["fixture-classifier", "fixture-answer"],
        }
        assert rpc(2000, "claim_receipts", claim)["status"] == 403
        assert rpc(2002, "claim_receipts", claim)["status"] == 200
        assert client(2001, "reserve", a, backend=True)["status"] == "filesystem_denied"
        assert client(2000, "reserve", a, backend=True)["status"] == "filesystem_denied"
        assert client(2001, "tcp", 19080)["connect_errno"] != 0
        assert (
            client(2001, "tcp", ready["ports"]["http-ingress-server"])["connect_errno"]
            != 0
        )

        def admin(operation):
            code = "import json,subprocess,sys;x=json.load(sys.stdin);print(subprocess.check_output(['docker','exec',x['name'],'/usr/sbin/chroot','/fixture','/usr/local/bin/python3','/opt/probe.py','control',x['operation']],stderr=subprocess.PIPE,timeout=50).decode())"
            text = remote(
                host, code, {"name": name, "operation": operation}, timeout=60
            )
            assert text.startswith("200 "), text

        admin("/restart-journal-backend")
        assert (
            rpc(2000, "reserve", a)["status"] == 503
        )  # old backend inode remains fenced
        admin("/restart-frontend")
        assert (
            rpc(
                0, "initialize", bootstrap | {"opening_days": {str(now // 86400000): 0}}
            )["status"]
            == 409
        )
        assert rpc(2000, "reserve", a)["body"] == "Unknown"
        assert rpc(2000, "begin", a)["status"] == 409
        assert rpc(2000, "reserve", call("d"))["body"] == "Denied"
        assert (
            rpc(2002, "claim_receipts", claim | {"manifest_sha256": "9" * 64})["status"]
            == 409
        )
        receipt = claim | {
            "route_sha256": "e" * 64,
            "components": {"classifier": "3" * 64, "answer": "4" * 64},
            "billed_microusd": 2,
        }
        assert rpc(2002, "complete", receipt)["status"] == 200
        # A day-only refund of A's600000 reserve to actual2 would admit E at
        # 4500002; retaining reservations correctly denies E at5100000.
        assert rpc(2000, "reserve", call("e"))["body"] == "Denied"
        assert rpc(0, "revoke", scopes[("a", 1)])["status"] == 200
        scope("a", 2, 200000)
        assert rpc(2000, "reserve", call("a", 2))["body"] == "Denied"
        result = metadata | {
            "purpose": PURPOSE,
            "native_arch": "x86_64",
            "synthetic": True,
            "candidate_enabled": False,
            "completed_live_runs": 0,
            "source_sha256": source,
            "broker_client_source_sha256": {
                name: hashlib.sha256(data.encode()).hexdigest()
                for name, data in broker_sources.items()
            },
            "checks": {
                "kernel_uid_roles": True,
                "protected_python_broker_client": True,
                "worker_backend_filesystem_denied": True,
                "broker_backend_filesystem_denied": True,
                "worker_sdk_tcp_denied": True,
                "worker_journal_tcp_denied": True,
                "backend_socket_replacement_fenced": True,
                "unknown_survived_sigkill": True,
                "daily_denial_survived_sigkill": True,
                "receipt_claim_survived_sigkill": True,
                "task_cap_preserved_across_attempts": True,
                "actual_cost_did_not_refund_reservation": True,
                "day_cap_preserved_after_settlement": True,
                "opening_budget_reset_refused": True,
            },
        }
        admin("/stop")
        return result
    finally:
        remote(
            host,
            "import json,subprocess,sys;x=json.load(sys.stdin);subprocess.run(['docker','rm','-f',x['name']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)",
            {"name": name},
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="hermes-control")
    parser.add_argument(
        "--stage", required=True, help="fresh source-built owned fixture stage"
    )
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    if args.summary.exists():
        raise SystemExit("refusing evidence overwrite")
    receipt = execute(args.host, args.stage)
    with args.summary.open("x") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    print(json.dumps(receipt, indent=2))
