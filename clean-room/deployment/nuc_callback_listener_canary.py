"""Actual socket activation into UID2000; create-only fixed canary and receipts."""
import hashlib,json,os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGH';BASE=old.RUN/'relay'/G;SOCKET=BASE/'relay.sock';PROBE=BASE/'probe.py'
NAME='sfactory-callback-listener-canary-20261030';SYSTEM=pathlib.Path('/run/systemd/system');UNIT=SYSTEM/(NAME+'.socket');SERVICE=SYSTEM/(NAME+'.service')
START=old.ETC/'callback-listener-canary-started.json';DONE=old.ETC/'callback-listener-canary-complete.json';PKG=old.PREFIX/'relay'
MODULE_SHA='e99c1f9580c473f9c91a3f31cb6445db98e6420d07d306088c05d3da9d6c0dcf'
PROBE_BYTES=("import os,sys\nsys.path.insert(0,"+repr(str(PKG))+")\nfrom nuc_relay_systemd import validate_listener\nif os.environ.get('LISTEN_PID')!=str(os.getpid()) or os.environ.get('LISTEN_FDS')!='1' or os.environ.get('LISTEN_FDNAMES')!='callback':raise RuntimeError('descriptor mismatch')\nvalidate_listener(3,"+repr(G)+")\nprint('listener_validated',flush=True)\n").encode()
UNIT_BYTES=('[Unit]\nDescription=Factory callback validation canary\n[Socket]\nListenStream='+str(SOCKET)+'\nSocketUser=root\nSocketGroup=sfgoose-worker\nSocketMode=0660\nFileDescriptorName=callback\nAccept=no\nRemoveOnStop=yes\nService='+NAME+'.service\n').encode()
SERVICE_BYTES=('[Unit]\nDescription=Factory callback validator canary\nRequires='+NAME+'.socket\nAfter='+NAME+'.socket\n[Service]\nType=oneshot\nUser=sfgoose-control\nGroup=sfgoose-control\nSockets='+NAME+'.socket\nExecStart=/usr/bin/python3 -I -B '+str(PROBE)+'\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nMemoryMax=64M\nTasksMax=16\nRuntimeMaxSec=20s\n').encode()
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def digest(b):return hashlib.sha256(b).hexdigest()
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (BASE,UNIT,SERVICE,START,DONE)),'canary state occupied')
 old.directory(old.RUN/'relay',0,0,0o755);old.directory(SYSTEM,0,0,0o755);old.read(PKG/'nuc_relay_systemd.py',0o444,MODULE_SHA)
 package=json.loads(old.read(old.ETC/'relay-package.json',0o600));require(package['files'].get('nuc_relay_systemd.py')==MODULE_SHA,'relay package mismatch')
 for name,sha in package['files'].items():
  require(re.fullmatch(r'[A-Za-z0-9_.-]+',name) and re.fullmatch(r'[0-9a-f]{64}',sha),'package entry invalid');old.read(PKG/name,0o444,sha,1_000_000)
 for n in (NAME+'.socket',NAME+'.service'):require(old.ctl('show',n,'-p','LoadState','--value')=='not-found','canary unit occupied')
 return {'generation':G,'socket_unit':str(UNIT),'service_unit':str(SERVICE),'unit_sha256':digest(UNIT_BYTES),'service_sha256':digest(SERVICE_BYTES),'probe_sha256':digest(PROBE_BYTES),'module_sha256':MODULE_SHA,'scope':'private inherited listener only; no generation claim or provider'}
def journal():
 p=subprocess.run(['/usr/bin/journalctl','--boot','-u',NAME+'.service','--no-pager','-o','json','--output-fields=MESSAGE,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_UID'],env=old.ENV,capture_output=True,timeout=15,check=True);require(len(p.stdout)<=65536 and len(p.stderr)<=8192,'journal exceeds bound');records=[]
 for line in p.stdout.splitlines():
  obj=json.loads(line)
  if obj.get('MESSAGE')!='listener_validated':continue
  inv=obj.get('_SYSTEMD_INVOCATION_ID');require(obj.get('_SYSTEMD_UNIT')==NAME+'.service' and obj.get('_UID')=='2000' and isinstance(inv,str) and re.fullmatch(r'[0-9a-f]{32}',inv),'journal identity mismatch');records.append(inv)
 require(len(records)==1,'journal result ambiguous');return records[0]
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 os.mkdir(BASE,0o710);os.chmod(BASE,0o710);os.chown(BASE,0,2000);old.syncdir(BASE.parent);old.store(PROBE,PROBE_BYTES,0o444);old.store(UNIT,UNIT_BYTES,0o644);old.store(SERVICE,SERVICE_BYTES,0o644);old.ctl('daemon-reload')
 for path in (UNIT,SERVICE):
  props=dict(line.split('=',1) for line in old.ctl('show',path.name,'--property=LoadState,Names,FragmentPath,DropInPaths','--no-pager').splitlines());require(props=={'LoadState':'loaded','Names':path.name,'FragmentPath':str(path),'DropInPaths':''},'unit mismatch')
 old.ctl('start',NAME+'.socket');s=os.lstat(SOCKET);require(stat.S_ISSOCK(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(0,2001,0o660),'socket mismatch')
 old.ctl('start',NAME+'.service');props=dict(line.split('=',1) for line in old.ctl('show',NAME+'.service','--property=ActiveState,SubState,MainPID,Result,ExecMainStatus,Job','--no-pager').splitlines());require(props.get('ActiveState')=='inactive' and props.get('MainPID')=='0' and props.get('Result')=='success' and props.get('ExecMainStatus')=='0' and props.get('Job','') in ('','0'),'service outcome unresolved');inv=journal()
 old.ctl('stop',NAME+'.socket');require(old.ctl('show',NAME+'.socket','-p','ActiveState','--value')=='inactive' and not os.path.lexists(SOCKET),'socket cleanup unresolved')
 for path,data,mode in ((PROBE,PROBE_BYTES,0o444),(UNIT,UNIT_BYTES,0o644),(SERVICE,SERVICE_BYTES,0o644)):old.read(path,mode,digest(data));os.unlink(path);old.syncdir(path.parent)
 os.rmdir(BASE);old.syncdir(BASE.parent);old.ctl('daemon-reload')
 result={'actual_systemd_listener_validated':True,'uid':2000,'invocation_id':inv,'cleanup_complete':True,'provider_called':False};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
