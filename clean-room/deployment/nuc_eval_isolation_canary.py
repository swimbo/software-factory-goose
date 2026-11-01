"""Fixed synthetic UID2001 isolation canary, source only until reviewed."""
import hashlib,json,os,pathlib,re,stat,subprocess,time
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGM';TASK='01M65RMR3FE6FQTFRBHERRHXSM';ROOT=old.ETC;STATE=pathlib.Path('/var/lib/software-factory-goose');SNAP=STATE/'evaluator-isolation'/G;SLICE='sfactory'+G.lower()+'.slice';UNIT=old.UNIT/SLICE
INTENT=ROOT/'evaluator-isolation-canary-started.json';DONE=ROOT/'evaluator-isolation-canary-complete.json';SECRET='/home/bo/.hermes/bifrost/factory-secrets/software-factory-goose/credential';HOLDOUT='/usr/local/libexec/software-factory-goose/evaluator/nuc_registry_evaluator.py'
CODE=b'''import os,pathlib,socket,sys\nf=dict(x.split(":",1) for x in pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in x)\nif os.getuid()!=2001 or os.geteuid()!=2001 or os.getgid()!=2001 or os.getegid()!=2001 or f.get("NoNewPrivs","").strip()!="1" or f.get("Seccomp","").strip()!="2" or 2002 in os.getgroups() or any(int(f[k].strip(),16)!=0 for k in ("CapEff","CapPrm","CapInh","CapBnd","CapAmb")):raise RuntimeError("worker restrictions unavailable")\nfor p in ("/home/bo/.hermes/bifrost/factory-secrets/software-factory-goose/credential","/usr/local/libexec/software-factory-goose/evaluator/nuc_registry_evaluator.py"):\n try:fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);os.close(fd)\n except OSError:continue\n raise RuntimeError("host file accessible")\ns=socket.socket();s.settimeout(1)\ntry:s.connect(("127.0.0.1",9084))\nexcept OSError:pass\nelse:raise RuntimeError("host network accessible")\nfinally:s.close()\nprint("isolation_passed")\n'''
SLICE_UNIT=b'[Unit]\nDescription=Software factory synthetic evaluator isolation\n[Slice]\nMemoryMax=128M\nTasksMax=32\nCPUQuota=50%\n'
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def require(x,msg):
 if not x:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (INTENT,DONE,SNAP,UNIT,ROOT/'tasks'/(G+'.json'),ROOT/'deadline-grants'/(G+'.json'),pathlib.Path('/sys/fs/cgroup')/SLICE)),'fixture occupied')
 for p,mode,uid,gid in ((pathlib.Path(SECRET),0o600,1000,1000),(pathlib.Path(HOLDOUT),0o440,0,2002)):
  st=os.lstat(p);require(stat.S_ISREG(st.st_mode) and (stat.S_IMODE(st.st_mode),st.st_uid,st.st_gid,st.st_nlink)==(mode,uid,gid,1),'protected host file unavailable')
 for u in (SLICE,'sfactorydeadline'+G.lower()+'.timer','sfactorydeadline'+G.lower()+'.service','sfactory-eval-isolation-host-'+G.lower()+'.service'):
  require(old.ctl('show',u,'-p','ActiveState','--value')=='inactive' and old.ctl('show',u,'-p','Job','--value')=='','unit occupied')
  for root in ('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system'):
   for path in (pathlib.Path(root)/u,pathlib.Path(root)/(u+'.d'),pathlib.Path(root)/(u.rsplit('.',1)[1]+'.d')):require(not os.path.lexists(path),'unit alias occupied')
 backend_path=old.PREFIX/'evaluator'/'nuc_registry_eval_backend.py';old.directory(backend_path.parent,0,2002,0o710);fd=os.open(backend_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2002,1,0o440) and st.st_size<1000000,'backend unavailable');raw=os.read(fd,1000001);require(len(raw)==st.st_size and hashlib.sha256(raw).hexdigest()=='dc8cb24e1bda8f0ed525f80216c1c4361b8889f588287b3eaf44eb946368cffc','backend changed')
 finally:os.close(fd)
 helper=old.read(old.PREFIX/'root-launch-host.py',0o755,'604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e',1000000);h={'__name__':'eval_isolation_helper'};exec(compile(helper,'<pinned-helper>','exec'),h);d,_=h['modules']();h['engine_guard']();d.fixed_binary()
 for selector in ('label=org.software-factory.evaluation='+G,'name=^/sfactoryeval'+G.lower()+'$'):require(not h['fixed_run'](h['DOCKER']+['ps','-a','--filter',selector,'--format','{{.ID}}']).strip(),'container occupied')
 return {'generation':G,'task':TASK,'program_sha256':hashlib.sha256(CODE).hexdigest(),'scope':'synthetic UID2001 isolation only; no credential read, model or provider'}

def apply(approved):
 require(plan()==approved,'isolation plan changed');old.store(INTENT,canon(approved),0o600)
 helper=old.read(old.PREFIX/'root-launch-host.py',0o755,'604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e',1000000);h={'__name__':'eval_isolation_helper'};exec(compile(helper,'<pinned-helper>','exec'),h);d,_=h['modules']();h['engine_guard']()
 parent=STATE/'evaluator-isolation'
 if not os.path.lexists(parent):os.mkdir(parent,0o700);os.chmod(parent,0o700);old.syncdir(STATE)
 old.directory(parent,0,0,0o700);os.mkdir(SNAP,0o755);os.chmod(SNAP,0o755);old.syncdir(parent);old.store(SNAP/'probe.py',CODE,0o444);os.chmod(SNAP,0o555);old.syncdir(parent)
 old.store(UNIT,SLICE_UNIT,0o644);old.ctl('daemon-reload');require(old.ctl('show',SLICE,'-p','FragmentPath','--value')==str(UNIT) and old.ctl('show',SLICE,'-p','DropInPaths','--value')=='','slice identity unavailable');old.ctl('start',SLICE)
 cg=pathlib.Path('/sys/fs/cgroup')/SLICE;st=cg.stat();events=(cg/'cgroup.events').read_text().splitlines();quota=(cg/'cpu.max').read_text().split();require(st.st_uid==0 and events.count('populated 0')==1 and events.count('frozen 0')==1 and (cg/'memory.max').read_text().strip()==str(128*1024**2) and (cg/'pids.max').read_text().strip()=='32' and len(quota)==2 and all(x.isdigit() for x in quota) and 2*int(quota[0])==int(quota[1]),'slice unavailable')
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();task={'schema':1,'target_id':G,'task_id':TASK,'generation':G,'boot_id':boot,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino};old.store(ROOT/'tasks'/(G+'.json'),canon(task),0o600)
 now=time.time_ns();grant={'schema':1,'target_id':G,'boot_id':boot,'catalog_sha256':hashlib.sha256(canon(task)).hexdigest(),'issued_unix_ns':now,'expires_unix_ns':now+100_000_000_000,'max_duration_seconds':100,'purpose':'synthetic-canary-only'};d.store(ROOT/'deadline-grants'/(G+'.json'),grant);armed=d.arm(d.plan(G));wake=armed['wake_monotonic_ns']
 def guard():
  s=cg.stat();e=(cg/'cgroup.events').read_text().splitlines();require((s.st_dev,s.st_ino)==(st.st_dev,st.st_ino) and e.count('frozen 0')==1 and not os.path.lexists(STATE/'stop'/(G+'.closed')) and time.monotonic_ns()<wake and d.property_value(armed['timer'],'ActiveState')=='active','deadline unavailable');h['engine_guard']()
 # A host process running as the actual worker identity may open neither path;
 # it opens descriptors only, never reads a byte of either file.
 host_code="""import os,pathlib\nf=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)\nif os.getuid()!=2001 or os.geteuid()!=2001 or os.getgid()!=2001 or os.getegid()!=2001 or f.get('NoNewPrivs','').strip()!='1' or any(int(f[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise RuntimeError('host worker identity unavailable')\nfor p in (%r,%r):\n try:f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);os.close(f)\n except PermissionError:continue\n raise RuntimeError('protected host file accessible')\nprint('host_access_denied')\n"""%(SECRET,HOLDOUT)
 client='sfactory-eval-isolation-host-'+G.lower()+'.service';old.store(STATE/'stop'/(G+'.host-check-intent'),canon({'unit':client}),0o600)
 p=subprocess.run(['/usr/bin/systemd-run','--unit='+client,'--wait','--pipe','--quiet','--property=User=sfgoose-worker','--property=Group=sfgoose-worker','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=PrivateNetwork=yes','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',host_code],env=old.ENV,capture_output=True,timeout=25,check=False);require(p.returncode==0 and p.stdout==b'host_access_denied\n' and len(p.stderr)<=8192,'host UID denial unavailable')
 guard();name='sfactoryeval'+G.lower();args=h['DOCKER']+['create','--name',name,'--label','org.software-factory.evaluation='+G,'--cgroup-parent',SLICE,'--network','none','--cgroupns','private','--ipc','private','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','32','--memory','128m','--cpus','0.5','--restart','no','--user','2001:2001','--pull','never','--log-driver','json-file','--log-opt','max-size=1m','--log-opt','max-file=2','--mount','type=bind,src='+str(SNAP)+',dst=/work,readonly','--entrypoint','/usr/local/bin/python3','sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937','-I','-B','/work/probe.py']
 old.store(STATE/'stop'/(G+'.create-intent'),canon({'name':name}),0o600);guard();ident=h['fixed_run'](args,timeout=30).decode().strip();require(re.fullmatch('[0-9a-f]{64}',ident),'create outcome unknown');old.store(STATE/'stop'/(G+'.created'),canon({'id':ident}),0o600);guard()
 # Import only the root-protected, reviewed v2 inspection implementation.
 sys_path=__import__('sys').path;sys_path.insert(0,str(old.PREFIX/'evaluator'));import nuc_registry_eval_backend as backend
 checker=backend.Backend.__new__(backend.Backend);checker.h=h;entry={'target':G,'snapshot_path':str(SNAP)};cmd=['-I','-B','/work/probe.py'];checker.inspect(entry,ident,name,'created',cmd)
 old.store(STATE/'stop'/(G+'.start-intent'),canon({'id':ident}),0o600);guard();code,out,err=checker.capture_start(h,ident);guard();require((code,out,err)==(0,b'isolation_passed\n',b''),'worker isolation unavailable')
 d.run('/usr/bin/systemctl','start',armed['timer'].removesuffix('.timer')+'.service',timeout=15);end=time.monotonic()+15
 while time.monotonic()<end:
  events=(cg/'cgroup.events').read_text().splitlines()
  if events.count('frozen 1')==1 and events.count('populated 0')==1:break
  time.sleep(.1)
 else:raise RuntimeError('kernel stop unresolved')
 s=cg.stat();require((s.st_dev,s.st_ino)==(st.st_dev,st.st_ino) and h['rootfile'](STATE/'stop'/(G+'.closed'))==(G+'\n').encode(),'closure unavailable')
 h['engine_guard']();actual=checker.inspect(entry,ident,name,'exited',cmd);require(actual.get('ExitCode')==0 and actual.get('StartedAt') not in (None,'','0001-01-01T00:00:00Z'),'container exit unavailable');old.store(STATE/'stop'/(G+'.remove-intent'),canon({'id':ident}),0o600);h['fixed_run'](h['DOCKER']+['rm',ident],timeout=15)
 p=subprocess.run(h['DOCKER']+['inspect',ident],env=old.ENV,capture_output=True,timeout=10,check=False);events=(cg/'cgroup.events').read_text().splitlines();s=cg.stat();require(p.returncode!=0 and len(p.stderr)<=8192 and b'no such object' in p.stderr.lower() and (s.st_dev,s.st_ino)==(st.st_dev,st.st_ino) and events.count('frozen 1')==1 and events.count('populated 0')==1,'removal unresolved');h['engine_guard']();d.run('/usr/bin/systemctl','stop',armed['timer'])
 result={'generation':G,'host_uid2001_denied':True,'container_uid2001_isolated':True,'no_network':True,'exact_id_removed':True,'frozen_empty':True,'credential_read':False,'provider_called':False};old.store(DONE,canon(result),0o600);return result
