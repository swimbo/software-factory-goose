"""One-shot real-sidecar registration; unknown results retain the running SDK."""
import hashlib,json,os,pathlib,re,socket,stat,subprocess,time
import nuc_registry_sidecar_install as install
import nuc_real_sidecar_activate as prior
import nuc_grant_sidecar_install as old
import nuc_grant_sidecar_resume as resume
import nuc_grant_admin_inspection as admin

START=old.ETC/'registry-activation-started.json';DONE=old.ETC/'registry-activation-complete.json';RECEIPT=old.ETC/'registry-registration-complete.json';REGISTRATION_START=old.ETC/'registry-registration-started.json'

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,RECEIPT,REGISTRATION_START,install.MARKER)),'activation already attempted')
 installed=json.loads(old.read(install.DONE,0o600));before=json.loads(old.read(install.START,0o600))
 require(installed=={'installed':True,'registered':False,'started':False,'claim_requested':False,'catalog_sha256':before['catalog_sha256'],'registry_sha256':before['registry_sha256']},'installation receipt mismatch')
 cfg,config,evidence,manifest=install.generated();require(old.read(install.CFG,0o644,before['config_sha256'])==config and old.read(install.EVIDENCE,0o644,before['evidence_sha256'])==evidence and old.read(install.MANIFEST,0o644,before['registry_sha256'])==manifest,'catalog changed')
 old.read(install.BIN,0o755,install.SOURCE_SHA,100_000_000);old.read(install.REGISTER,0o755,hashlib.sha256(install.REGISTER_SOURCE).hexdigest())
 for name,data in install.units().items():old.read(old.UNIT/name,0o644,hashlib.sha256(data).hexdigest())
 install.verify_loaded();require(old.old_snapshot()==before['old'] and old.sidecar_running()==before['prior_sidecar'] and prior.service_running()==before['real_sidecar'],'preserved service changed')
 require(not any(os.path.lexists(old.RUN/n) for n in ('registry-intake.sock','registry-worker.sock','registry-launch-grant.sock')),'registry socket already exists')
 resume.old_inspect();return {'install':before,'scope':'single non-force registration on 9084; no task claim or engine'}

def registration():
 # Read the entire current-boot unit journal, never a live oneshot InvocationID.
 p=subprocess.run(['/usr/bin/journalctl','--boot','-u',install.NAME+'register.service','--no-pager','-o','json','--output-fields=MESSAGE,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID'],env=old.ENV,capture_output=True,timeout=15,check=True)
 require(len(p.stdout)<=65536 and len(p.stderr)<=8192,'registration log exceeds bound');entries=[]
 for line in p.stdout.splitlines():
  record=json.loads(line);msg=record.get('MESSAGE')
  if not isinstance(msg,str) or not msg.startswith('REGISTRY_REGISTRATION '):continue
  inv=record.get('_SYSTEMD_INVOCATION_ID');require(record.get('_SYSTEMD_UNIT')==install.NAME+'register.service' and isinstance(inv,str) and re.fullmatch(r'[0-9a-f]{32}',inv),'registration invocation mismatch')
  value=json.loads(msg.removeprefix('REGISTRY_REGISTRATION '));require(set(value)=={'id','service_count'} and isinstance(value['id'],str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',value['id']) and value['service_count']==4,'registration result mismatch')
  entries.append({'deployment_id':value['id'],'invocation_id':inv,'service_count':4})
 require(len(entries)==1,'registration outcome not unique');return entries[0]

def service_running():
 # Reuse the same precise loaded PID, cgroup and socket checks as the canary.
 props=dict(line.split('=',1) for line in old.ctl('show',install.NAME+'runtime.service','--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,ControlGroup','--no-pager').splitlines())
 name=install.NAME+'runtime.service';require(props.get('LoadState')=='loaded' and props.get('ActiveState')=='active' and props.get('Names')==name and props.get('FragmentPath')==str(old.UNIT/name) and props.get('DropInPaths','')=='' and int(props.get('MainPID','0'))>1,'real service unavailable')
 group='/system.slice/'+name;require(props.get('ControlGroup')==group,'real cgroup mismatch');path=pathlib.Path('/sys/fs/cgroup'+group);st=os.stat(path);quota=(path/'cpu.max').read_text().split()
 require(st.st_uid==0 and (path/'memory.max').read_text().strip()==str(512*1024**2) and (path/'pids.max').read_text().strip()=='128' and len(quota)==2 and all(x.isdigit() for x in quota) and int(quota[0])==int(quota[1]),'real kernel limits mismatch')
 sockets={}
 for filename,gid,mode in [('registry-intake.sock',1000,0o660),('registry-worker.sock',2001,0o660),('registry-launch-grant.sock',0,0o600)]:
  p=old.RUN/filename;s=os.lstat(p);require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0 and s.st_gid==gid and stat.S_IMODE(s.st_mode)==mode,'real socket mismatch')
  try:os.getxattr(p,'system.posix_acl_access',follow_symlinks=False)
  except OSError as e:require(e.errno==old.errno.ENODATA,'real socket ACL unavailable')
  else:raise RuntimeError('real socket ACL forbidden')
  sockets[filename]={'dev':s.st_dev,'ino':s.st_ino,'gid':gid,'mode':mode}
 return {'pid':int(props['MainPID']),'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'sockets':sockets}

def metadata(deployment):
 admin.DEPLOYMENT=deployment;admin.NAME='sfactory-registry-admin-inspect-'+hashlib.sha256(deployment.encode()).hexdigest()[:16]+'.service'
 # Probe source pins port 9082 in comparison; adjust only its literal expected endpoint.
 admin.PROBE_SOURCE=admin.PROBE_SOURCE.replace('parsed.port==9082','parsed.port==9084')
 host=admin.Host(source_digest='registry-sidecar-activation-v1');result=admin.apply(host,admin.make_plan(host));m=result['metadata']
 require(result['deployment']==deployment and m.get('id_matches') is True and m.get('uri_matches') is True,'deployment metadata mismatch')
 actual={}
 for x in m.get('service_entries',[]):
  n=x.get('name');require(n in resume.EXPECTED and n not in actual and x.get('deployment_matches') is True and x.get('revision')==4,'service revision mismatch');actual[n]=x.get('handler_names')
 require(actual==resume.EXPECTED,'service handlers changed');return m['response_sha256']

def canary_history():
 code=r'''import http.client,json,socket
class Conn(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(10);self.sock.connect('/run/software-factory-goose/grant-intake.sock')
c=Conn('localhost',timeout=10);body=json.dumps({'key':'01M65GTQYKXECJWHCPKQD248SY'}).encode()
c.request('POST','/inspect',body,{'Content-Type':'application/json','Connection':'close'});r=c.getresponse();raw=r.read(65537)
if r.status!=200 or len(raw)>65536 or json.loads(raw).get('intent_id')!='01M65GTQYKXECJWHCPKQD248SY':raise RuntimeError('canary history unavailable')
'''
 p=resume.role_probe('bo',['/usr/bin/python3','-I','-B','-c',code],25);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'prior canary history unavailable')

def real_history():
 code=r"""import http.client,json,socket
class Conn(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(10);self.sock.connect('/run/software-factory-goose/real-intake.sock')
c=Conn('localhost',timeout=10);b=json.dumps({'key':'01M65NEH5T1Z0JWW2YCV44DY01'}).encode();c.request('POST','/inspect',b,{'Content-Type':'application/json','Connection':'close'});r=c.getresponse();d=r.read(65537)
if r.status!=200 or len(d)>65536 or json.loads(d).get('intent_id')!='01M65NEH5T1Z0JWW2YCV44DY01':raise RuntimeError('real history unavailable')
"""
 p=resume.role_probe('bo',['/usr/bin/python3','-I','-B','-c',code],25);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'real history unavailable')

def postchecks():
 code=r'''import http.client,json,socket
class Conn(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(10);self.sock.connect('/run/software-factory-goose/registry-intake.sock')
c=Conn('localhost',timeout=10);body=json.dumps({'key':'01M65RMR3F959RPSERJ681DQ43'}).encode()
c.request('POST','/inspect',body,{'Content-Type':'application/json','Connection':'close'});r=c.getresponse();data=r.read(8193)
if r.status!=200 or len(data)>8192 or json.loads(data) is not None:raise RuntimeError('real intake is not empty')
'''
 p=resume.role_probe('bo',['/usr/bin/python3','-I','-B','-c',code],25);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'real intake unavailable or not empty')
 code="import socket;s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect('/run/software-factory-goose/registry-launch-grant.sock')"
 p=resume.role_probe('sfgoose-worker',['/usr/bin/python3','-I','-B','-c',code],25);require(p.returncode!=0 and b'PermissionError' in p.stderr,'worker grant socket not denied')
 for generation,expected in [('01M65RMR3F04YB1B016EBBSXGH',403),(catalog_generation(),503)]:
  body=json.dumps({'generation':generation},separators=(',',':')).encode();sock=socket.socket(socket.AF_UNIX);sock.settimeout(15)
  try:
   sock.connect(str(old.RUN/'registry-launch-grant.sock'));sock.sendall(b'POST /reserve HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
   import http.client
   response=http.client.HTTPResponse(sock);response.begin();data=response.read(16385);require(response.status==expected and len(data)<=16384,'grant preclaim denial not proven')
  finally:sock.close()

def catalog_generation():return install.GEN

def apply(approved):
 require(plan()==approved,'activation plan changed');old.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 for suffix in ('intake.socket','worker.socket','launch.socket','runtime.service'):old.ctl('start',install.NAME+suffix)
 running=service_running();require(old.old_snapshot()==approved['install']['old'] and old.sidecar_running()==approved['install']['prior_sidecar'] and prior.service_running()==approved['install']['real_sidecar'],'preserved service changed')
 # Registration can commit even if this call fails. Never retry or stop the SDK on ambiguity.
 old.store(REGISTRATION_START,b'one non-force registration at 9084\n',0o600)
 old.ctl('start',install.NAME+'register.service');receipt=registration();old.store(RECEIPT,json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 digest=metadata(receipt['deployment_id']);resume.old_inspect();canary_history();real_history()
 require(old.old_snapshot()==approved['install']['old'] and old.sidecar_running()==approved['install']['prior_sidecar'] and prior.service_running()==approved['install']['real_sidecar'] and service_running()==running,'service changed')
 # The marker opens only fixed UDS; if its write is ambiguous, close the runtime.
 marker_identity=None
 try:
  old.store(install.MARKER,b'private canary bootstrap completed; acceptance tests required\n',0o644)
  marker_created=os.lstat(install.MARKER);marker_identity=(marker_created.st_dev,marker_created.st_ino)
  time.sleep(.3);postchecks();resume.old_inspect();canary_history();real_history()
  require(old.old_snapshot()==approved['install']['old'] and old.sidecar_running()==approved['install']['prior_sidecar'] and prior.service_running()==approved['install']['real_sidecar'] and service_running()==running,'service changed')
  result={'registration':receipt,'deployment_metadata_sha256':digest,'sidecar':running,'production_accepted':False,'engine_enabled':False,'task_submitted':False,'old_and_canary_histories_readable':True,'new_intake_empty':True,'worker_socket_denied':True,'wrong_generation_denied':True,'unclaimed_grant_denied':True}
  old.store(DONE,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return result
 except Exception:
  try:
   if marker_identity is not None:
    marker=os.lstat(install.MARKER);require(stat.S_ISREG(marker.st_mode) and marker.st_uid==0 and (marker.st_dev,marker.st_ino)==marker_identity,'marker changed')
    os.unlink(install.MARKER);old.syncdir(old.ETC)
  finally:
   for suffix in ('intake.socket','worker.socket','launch.socket','runtime.service'):
    try:old.ctl('stop',install.NAME+suffix)
    except Exception:pass
  raise
