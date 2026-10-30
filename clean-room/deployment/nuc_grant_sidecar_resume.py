"""One-shot retained registration resume; no registration, launch, or state reset.

Imported by a root-pinned bridge together with the reviewed sibling modules.
On any uncertain result preserve the new intent and stop only new ingress units.
"""
import hashlib,json,os,pathlib,socket,stat,subprocess,time,uuid
import nuc_grant_sidecar_install as install
import nuc_grant_failed_inventory as inventory
import nuc_grant_admin_inspection as admin

ETC=install.ETC; NAME=install.NAME
START=ETC/'grant-resume-started.json'; DONE=ETC/'grant-resume-complete.json'; MARKER=ETC/'grant-bootstrap-complete'
DID='dp_11wMFUQrAbq4s4S7B4ps6sN'; INVOCATION='f0b4931393934850af772df8b18b73f8'
CONFIG_SHA='70c14a65b8229304e04eb7e693eb7dc2ef20c7c947349e2e09e0b08dae84547f'
INTENT_SHA='004e32ebe4d4ae9da8fd8e69172cfa4def74c6e71705a1b75c5953852409dd4e'
EXPECTED={
 'IntakeJournal':['inspect','submit'],
 'RuntimeIntakeJournal':['inspect','submit_and_schedule'],
 'WorkerQueueJournal':['complete','lookup_pull','pull','schedule'],
 'ClaimLeaseJournal':['claim','complete','initialize','reexport_claim_history','renew','reserve_current_launch','reserve_launch','status'],
}
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C'}

def require(value,msg):
 if not value:raise RuntimeError(msg)

def verify_metadata(result):
 m=result['metadata']; require(result['deployment']==DID and m.get('id_matches') is True and m.get('uri_matches') is True,'deployment identity mismatch')
 entries=m.get('service_entries');require(isinstance(entries,list) and len(entries)==4,'service count mismatch')
 actual={}
 for e in entries:
  name=e.get('name');require(name in EXPECTED and name not in actual and e.get('deployment_matches') is True and e.get('revision')==2,'service identity mismatch')
  actual[name]=e.get('handler_names')
 require(actual==EXPECTED,'handler manifest mismatch')
 return m['response_sha256']

def plan():
 require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE) and not os.path.lexists(MARKER),'resume already attempted or marker exists')
 started=json.loads(install.read(install.INTENT,0o600,INTENT_SHA)); require(not os.path.lexists(install.DONE),'unexpected completion')
 install.read(ETC/'grant-runtime.json',0o644,CONFIG_SHA)
 install.read(ETC/'grant-evidence.json',0o644,'b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a')
 install.read(install.PREFIX/'private-grant-sidecar',0o755,install.SOURCE_SHA,100_000_000)
 install.read(install.PREFIX/'private-grant-register.py',0o755,install.REGISTER_SHA)
 for name,data in install.units().items(): install.read(install.UNIT/name,0o644,hashlib.sha256(data).hexdigest())
 install.verify_new_units();before=install.old_snapshot();require(before==started['old_snapshot'],'old service identity changed')
 found=inventory.inventory(); reg=found['registration'];require(reg=={'invocation_id':INVOCATION,'deployment_id':DID,'service_count':4},'registration record mismatch')
 u=found['units'][NAME+'register.service'];require(u.get('ExecMainStatus')=='0' and u.get('Result')=='success','registration result mismatch')
 expected_sockets={
  'grant-intake.sock':{'dev':25,'ino':2608035,'uid':0,'gid':1000,'mode':0o660,'type':stat.S_IFSOCK},
  'grant-worker.sock':{'dev':25,'ino':2608036,'uid':0,'gid':2001,'mode':0o660,'type':stat.S_IFSOCK},
  'launch-grant.sock':{'dev':25,'ino':2608037,'uid':0,'gid':0,'mode':0o600,'type':stat.S_IFSOCK},
 }
 require(found['sockets']==expected_sockets,'stale socket identity mismatch')
 for name in expected_sockets:
  path=install.RUN/name
  try:os.getxattr(path,'system.posix_acl_access',follow_symlinks=False)
  except OSError as exc:require(exc.errno==install.errno.ENODATA,'socket ACL unavailable')
  else:raise RuntimeError('socket ACL forbidden')
 return {'old':before,'registration':reg,'config_sha256':CONFIG_SHA,'started_sha256':INTENT_SHA,'operation':'start only retained canary sidecar; no registration or engine'}


def role_probe(role,argv,timeout):
 require(role in ('bo','sfgoose-worker'),'unapproved probe identity')
 unit='sfactory-grant-readiness-'+uuid.uuid4().hex+'.service'
 command=['/usr/bin/systemd-run','--unit='+unit,'--collect','--wait','--pipe','--quiet','--property=User='+role,'--property=Group='+role,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=MemoryMax=128M','--property=TasksMax=32','--property=CPUQuota=50%','--property=RuntimeMaxSec=20s',*argv]
 return subprocess.run(command,env=ENV,capture_output=True,timeout=timeout,check=False)

def old_inspect():
 install.read(pathlib.Path('/usr/local/libexec/software-factory-goose/sfctl'),0o755,'d83b2d93a8cc4b7fddce6c435bafbbdf2b4b2c925d52a713398c4282729f1c6e',100_000_000)
 p=role_probe('bo',['/usr/local/libexec/software-factory-goose/sfctl','--json','private','inspect','01ARZ3NDEKTSV4RRFFQ69G5FAZ'],25)
 require(p.returncode==0 and len(p.stdout)<=65536 and len(p.stderr)<=8192,'old intake unavailable');value=json.loads(p.stdout);require(value.get('intent_id')=='01ARZ3NDEKTSV4RRFFQ69G5FAZ','old intake identity mismatch')

def grant_status(generation):
 body=json.dumps({'generation':generation},separators=(',',':')).encode(); request=b'POST /reserve HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(15)
 try:
  s.connect('/run/software-factory-goose/launch-grant.sock');s.sendall(request);buf=bytearray()
  while len(buf)<=16384:
   chunk=s.recv(4096)
   if not chunk:break
   buf.extend(chunk)
  require(len(buf)<=16384,'grant response too large');first=bytes(buf).split(b'\r\n',1)[0].split();require(len(first)>=2 and first[1].isdigit(),'grant response invalid');return int(first[1])
 finally:s.close()

def new_intake_empty():
 code=r'''import http.client,json,socket
class Conn(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(10);self.sock.connect('/run/software-factory-goose/grant-intake.sock')
c=Conn('localhost',timeout=10);body=json.dumps({'key':'01M65GTQYKXECJWHCPKQD248SY'}).encode()
c.request('POST','/inspect',body,{'Content-Type':'application/json','Connection':'close'});r=c.getresponse();data=r.read(8193)
if r.status!=200 or len(data)>8192 or json.loads(data) is not None:raise RuntimeError('new intake is not empty')
'''
 p=role_probe('bo',['/usr/bin/python3','-I','-B','-c',code],25)
 require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'new intake not empty or unavailable')

def peer_denied():
 # Kernel socket mode denies the unprivileged worker before any HTTP request.
 code="import socket;s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect('/run/software-factory-goose/launch-grant.sock')"
 p=role_probe('sfgoose-worker',['/usr/bin/python3','-I','-B','-c',code],25)
 require(p.returncode!=0 and b'PermissionError' in p.stderr,'worker was not denied by socket permissions')

def apply(approved):
 require(plan()==approved,'resume plan changed')
 install.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 marker_identity=None
 try:
  # Unique v3 probe, same reviewed fixed GET source. No registration call.
  admin.NAME=admin.NAME.replace('-v2.service','-v3.service')
  host=admin.Host(source_digest='retained-resume-v1'); probeplan=admin.make_plan(host);digest=verify_metadata(admin.apply(host,probeplan))
  for suffix in ('intake.socket','worker.socket','launch.socket','runtime.service'):install.ctl('start',NAME+suffix)
  running=install.sidecar_running();require(install.old_snapshot()==approved['old'],'old service identity changed')
  old_inspect()
  # Marker opens canary UDS only after the fixed deployment and old history checks.
  install.store(MARKER,b'private canary bootstrap completed; acceptance tests required\n',0o644)
  s=os.lstat(MARKER);marker_identity=(s.st_dev,s.st_ino)
  time.sleep(.3)
  new_intake_empty();peer_denied();require(grant_status('01M65GTQYKNHFXSJSZ55D7T363')==403,'wrong generation not denied')
  require(grant_status(install.GEN)==503,'unclaimed grant not denied')
  old_inspect();require(install.old_snapshot()==approved['old'] and install.sidecar_running()==running,'service identity changed')
  result={'registration':approved['registration'],'deployment_metadata_sha256':digest,'sidecar':running,'old_intake_readable':True,'new_intake_empty':True,'worker_socket_denied':True,'wrong_generation_denied':True,'unclaimed_grant_denied':True,'production_accepted':False,'engine_enabled':False}
  install.store(DONE,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
  return result
 except Exception:
  try:
   if marker_identity is not None:
    s=os.lstat(MARKER);require((s.st_dev,s.st_ino)==marker_identity and stat.S_ISREG(s.st_mode),'marker changed; manual reconciliation required')
    os.unlink(MARKER);install.syncdir(ETC)
  finally:
   for suffix in ('intake.socket','worker.socket','launch.socket','runtime.service'):
    try:install.ctl('stop',NAME+suffix)
    except Exception:pass
  raise
