"""Start only the fixed provisioned Unix-admin Restate; transition stays closed."""
import json,os,pathlib,re,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_retirement_coordinator as retired
import nuc_registry_offline_backup as backup
import nuc_registry_pinned_binary as pinned_binary
import nuc_registry_unix_restate_provision as provision
T=retired.T;START=gate.ROOT/'history'/(T+'.unix-restate-activation-started.json');DONE=gate.ROOT/'history'/(T+'.unix-restate-activation-complete.json')
PROBES={'journal':'sfactory-registry-unix-admin-journal-'+T.lower()+'.service','control':'sfactory-registry-unix-admin-control-'+T.lower()+'.service'}
def require(v,m):
 if not v:raise RuntimeError(m)
def old_restate_fenced():
 bplan=gate._json(old.read(backup.START,0o600,maxsize=1000000));retired.terminal(backup.RESTATE,bplan['restate']);old.read(backup.FENCE,0o600,backup.sha(b'offline\n'));old.read(backup.DROP,0o644,backup.sha(backup.dropin()));backup.verify_loaded_fence(bplan['restate'])
def plan_locked():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)),'activation occupied');retired_raw,_=backup.retirement_state();bplan=gate._json(old.read(backup.START,0o600,maxsize=1000000));retired.terminal(backup.RESTATE,bplan['restate']);old.read(backup.FENCE,0o600,backup.sha(b'offline\n'));backup.verify_loaded_fence(bplan['restate'])
 p=gate._json(old.read(provision.DONE,0o600));require(p.get('schema')==1 and p.get('transition_id')==T and p.get('started') is False and p.get('data_changed') is False and p.get('unit_sha256')==backup.sha(provision.unit()) and p.get('config_sha256')==backup.sha(provision.CONF) and p.get('probe_sha256')==provision.PROBE_SHA,'provision unavailable')
 old.read(old.UNIT/provision.UNIT,0o644,p['unit_sha256']);old.read(provision.CONFIG,0o644,p['config_sha256']);old.read(provision.PROBE,0o755,p['probe_sha256']);pinned_binary.verify(backup.BINARY,backup.BINARY_SHA);old.directory(backup.SOURCE.parent,2004,2004,0o700);old.directory(backup.SOURCE,2004,2004,0o755);old.directory(backup.SOURCE/'sfgoose-private',2004,2004,0o755);st=backup.SOURCE.stat();require((st.st_dev,st.st_ino)==(bplan['source_dev'],bplan['source_ino']),'data changed')
 unit=retired.properties(provision.UNIT);require(unit.get('LoadState')=='loaded' and unit.get('Names')==provision.UNIT and unit.get('FragmentPath')==str(old.UNIT/provision.UNIT) and unit.get('DropInPaths','')=='' and unit.get('ActiveState')=='inactive' and unit.get('MainPID')=='0' and unit.get('Job','')=='','Unix Restate not inactive')
 admin=backup.SOURCE/'sfgoose-private'/'admin.sock';require(not os.path.lexists(admin),'admin socket already present')
 roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable')
 for name in PROBES.values():
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','probe occupied');stem=name.removesuffix('.service')
  for parent in map(pathlib.Path,roots):
   for n in [name,name+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(parent/n),'probe collision')
 return {'schema':1,'transition_id':T,'retirement_sha256':backup.sha(retired_raw),'provision_sha256':backup.sha(old.read(provision.DONE,0o600)),'data_dev':st.st_dev,'data_ino':st.st_ino,'namespace':bplan['preservation']['private_namespace'],'unit_sha256':p['unit_sha256'],'probe_sha256':p['probe_sha256'],'scope':'start only fixed Unix-admin Restate; verify role access, retain transition'}
def plan():
 with backup.locked():return plan_locked()
def role(name,namespace):
 unit=PROBES[name];user='sfgoose-journal' if name=='journal' else 'sfgoose-control';args=['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--quiet','--property=User='+user,'--property=Group='+user,'--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+retired.attestation.ANCHOR_UNIT,'--property=BindsTo='+retired.attestation.ANCHOR_UNIT,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B',str(provision.PROBE),name]
 data=backup.canonical({'namespace_dev':namespace[0],'namespace_ino':namespace[1]});p=subprocess.run(args,input=data,env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'role proof unavailable');result=gate._json(p.stdout);require(old.ctl('show',unit,'-p','MainPID','--value')=='0' and old.ctl('show',unit,'-p','Job','--value')=='','role probe not terminal');return result
def apply(approved):
 with backup.locked():
  require(plan_locked()==approved,'activation changed');old.store(START,backup.canonical(approved),0o600);old_restate_fenced();old.ctl('start',provision.UNIT)
  p=retired.observe(provision.UNIT);require(p.get('ActiveState')=='active' and int(p.get('MainPID','0'))>1 and p.get('Job','')=='' and p.get('Names')==provision.UNIT and p.get('fragment_sha256')==approved['unit_sha256'],'Unix Restate outcome unknown')
  require(p.get('DropInPaths','')=='' and p.get('ControlGroup')=='/system.slice/'+provision.UNIT and re.fullmatch(r'[0-9a-f]{32}',p.get('InvocationID','')) and p['InvocationID']!='0'*32,'Unix Restate identity unavailable')
  for key,value in (('User','sfgoose-journal'),('Group','sfgoose-journal'),('PrivateNetwork','yes'),('JoinsNamespaceOf',retired.attestation.ANCHOR_UNIT),('BindsTo',retired.attestation.ANCHOR_UNIT),('NoNewPrivileges','yes'),('CapabilityBoundingSet','')):require(old.ctl('show',provision.UNIT,'-p',key,'--value')==value,'Unix Restate sandbox unavailable')
  fields={k:v.split() for k,v in (line.split(':',1) for line in pathlib.Path('/proc',p['MainPID'],'status').read_text().splitlines() if ':' in line)};require(fields.get('Uid')==['2004']*4 and fields.get('Gid')==['2004']*4 and fields.get('NoNewPrivs')==['1'] and all(fields.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')),'Unix Restate credentials unavailable')
  path=backup.SOURCE/'sfgoose-private'/'admin.sock';end=time.monotonic()+60
  while time.monotonic()<end and not os.path.lexists(path):time.sleep(.2)
  require(os.path.lexists(path),'Unix admin unavailable');journal=role('journal',approved['namespace']);control=role('control',approved['namespace']);require(set(journal)=={'schema','admin_ok','tcp_admin_absent','socket_dev','socket_ino'} and journal['schema']==1 and journal['admin_ok'] is True and journal['tcp_admin_absent'] is True and control=={'schema':1,'admin_denied':True,'tcp_admin_absent':True},'role proof failed')
  st=os.lstat(path);require((st.st_dev,st.st_ino)==(journal['socket_dev'],journal['socket_ino']),'admin socket changed');require(retired.observe(provision.UNIT)==p,'Unix Restate changed');current,_=backup.retirement_state();require(backup.sha(current)==approved['retirement_sha256'],'retirement changed');old_restate_fenced()
  result={'schema':1,'transition_id':T,'unit':provision.UNIT,'identity':p,'namespace':approved['namespace'],'data_dev':approved['data_dev'],'data_ino':approved['data_ino'],'socket_dev':st.st_dev,'socket_ino':st.st_ino,'journal_admin_ok':True,'control_admin_denied':True,'tcp_admin_absent':True,'gate_closed':True};old.store(DONE,backup.canonical(result),0o600);return result
