"""Start one fixed synthetic UID2000 probe and persist its before-fence receipt."""
import hashlib,json,os,pathlib,re,stat,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as active
import nuc_unix_admin_h2_sdk_install as package
import nuc_unix_admin_h2_probe_install as probe_install
UNIT='sfactory-unix-admin-h2-canary-ingress-probe.service';LOG=base.ROOT/'handshake'/'ingress-probe.log';START=old.ETC/'unix-admin-h2-canary-ingress-probe-started.json';DONE=old.ETC/'unix-admin-h2-canary-before-retirement.json';EPOCH=old.ETC/'unix-admin-h2-canary-activation-complete.json';OLD=old.ETC/'unix-admin-h2-canary-sdk-old-start-complete.json';REG=old.ETC/'unix-admin-h2-canary-register-old-complete.json'
PROBE=probe_install.DEST;PROBE_SHA=probe_install.SHA
def require(v,m):
 if not v:raise RuntimeError(m)
def canon(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'
def epoch():
 raw=old.read(EPOCH,0o600);e=json.loads(raw);require(e.get('schema')==1 and e.get('boot_id')==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() and e.get('fixture_retained_active') is True and e.get('production_data_used') is False,'epoch unavailable')
 for name in (base.NET,base.SERVER):require(active.identity(name)==e['identities'][name],'epoch process changed')
 return hashlib.sha256(raw).hexdigest()
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,LOG,package.HANDSHAKE/'old.retired',package.HANDSHAKE/'old.stopped')),'probe occupied')
 e=epoch();old.directory(package.HANDSHAKE,0,2000,0o710);old.read(PROBE,0o755,PROBE_SHA,65536)
 before=json.loads(old.read(OLD,0o600));reg=json.loads(old.read(REG,0o600));require(before.get('schema')==1 and before.get('unit')==package.OLD and before.get('uid')==2000 and before.get('caps_empty') is True and before.get('listener_ready') is True and reg.get('schema')==1 and reg.get('operation')=='register-old' and reg.get('service_name')=='FenceFixture' and reg.get('uri')=='http://127.0.0.1:9081' and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',reg.get('deployment_id','')),'old SDK unavailable')
 p=active.properties(package.OLD);require(p.get('ActiveState')=='active' and p.get('MainPID')==str(before['identity']['pid']) and p.get('Job','')=='' and old.ctl('show',package.OLD,'-p','InvocationID','--value')==before['identity']['invocation_id'],'old SDK changed')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','probe unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=5,check=True).stdout.decode().splitlines();require(paths and len(paths)<=64 and all(pathlib.Path(x).is_absolute() for x in paths),'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for root in map(pathlib.Path,paths):
  for name in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/name),'unit alias occupied')
 return {'epoch_sha256':e,'probe_source_sha256':PROBE_SHA,'old_deployment_id':reg['deployment_id'],'unit':UNIT,'scope':'one synthetic probe before retirement; no registration'}
def apply(approved):
 require(plan()==approved,'probe plan changed');old.store(START,canon(approved),0o600)
 fd=os.open(LOG,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:os.fchown(fd,0,2000);os.fchmod(fd,0o620);old.noacl(fd);os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(LOG.parent)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--quiet','--property=Type=exec','--property=RemainAfterExit=yes','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=After='+base.NET,'--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=StandardInput=null','--property=StandardOutput=append:'+str(LOG),'--property=StandardError=append:'+str(LOG),'--property=LimitFSIZE=1M','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=900s','/usr/bin/python3','-I','-B',str(PROBE)]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=20,check=False);require(p.returncode==0 and len(p.stderr)<=4096,'probe launch unknown')
 until=time.monotonic()+30;raw=b''
 while time.monotonic()<until:
  fd=os.open(LOG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2000,1,0o620) and st.st_size<=16384,'probe log unavailable');raw=os.read(fd,16385)
  finally:os.close(fd)
  if b'\n' in raw:break
  time.sleep(.1)
 require(raw.count(b'\n')==1 and raw.endswith(b'\n'),'probe result unknown');result=json.loads(raw);require(set(result)=={'stage','positive_old_count','direct_discovery','direct_reused','ingress_reused','hold','queued'} and result['stage']=='before_retirement' and type(result['positive_old_count']) is int and result['positive_old_count']==1 and result['direct_discovery'] is True and result['direct_reused'] is True and result['ingress_reused'] is True and all(isinstance(result[k],str) and re.fullmatch(r'[A-Za-z0-9_-]{1,256}',result[k]) for k in ('hold','queued')) and result['hold']!=result['queued'],'positive proof unavailable')
 require(old.ctl('show',UNIT,'-p','RemainAfterExit','--value')=='yes','probe retention unavailable')
 state=active.properties(UNIT);pid=int(state.get('MainPID','0'));inv=old.ctl('show',UNIT,'-p','InvocationID','--value');require(state.get('ActiveState')=='active' and pid>1 and state.get('Job','')=='' and state.get('User')=='sfgoose-control' and state.get('Group')=='sfgoose-control' and state.get('NoNewPrivileges')=='yes' and state.get('CapabilityBoundingSet')=='' and state.get('PrivateNetwork')=='yes' and state.get('JoinsNamespaceOf')==base.NET and state.get('BindsTo')==base.NET and state.get('DropInPaths','')=='' and state.get('ExecStart','').startswith('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+str(PROBE)+' ; ignore_errors=no ;') and state['ExecStart'].count('{ path=')==1 and re.fullmatch(r'[0-9a-f]{32}',inv),'probe identity unavailable')
 fields={k:v.split() for k,v in (line.split(':',1) for line in (pathlib.Path('/proc')/str(pid)/'status').read_text().splitlines() if ':' in line)}
 require(fields.get('Uid')==['2000']*4 and fields.get('Gid')==['2000']*4 and fields.get('NoNewPrivs')==['1'] and all(fields.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')),'probe process credentials unavailable')
 require(epoch()==approved['epoch_sha256'] and old.ctl('show',UNIT,'-p','MainPID','--value')==str(pid) and old.ctl('show',UNIT,'-p','InvocationID','--value')==inv,'probe changed')
 started=old.ctl('show',UNIT,'-p','ExecMainStartTimestampMonotonic','--value');require(started.isdigit() and int(started)>0,'probe start unavailable')
 receipt={'start_monotonic_us':int(started),'schema':1,'epoch_sha256':approved['epoch_sha256'],'probe_source_sha256':PROBE_SHA,'unit':UNIT,'pid':pid,'invocation_id':inv,'stdout_sha256':hashlib.sha256(raw).hexdigest(),**result,'probe_active':True,'no_job':True};old.store(DONE,canon(receipt),0o600);return receipt
