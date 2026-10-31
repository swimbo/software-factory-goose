"""One-shot owned v4-old retirement, with distinct fence and stopped markers."""
import json,os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as active
import nuc_unix_admin_h2_sdk_install as pkg
import nuc_unix_admin_h2_sdk_start as start
import nuc_unix_admin_h2_probe_install as probe_v2
START=old.ETC/'unix-admin-h2-canary-retirement-started.json';DONE=old.ETC/'unix-admin-h2-canary-retirement-complete.json'
FENCE=pkg.HANDSHAKE/'old.retired';STOPPED=pkg.HANDSHAKE/'old.stopped';CHECK='sfactory-unix-admin-h2-retired-listener-check.service'
def require(v,m):
 if not v:raise RuntimeError(m)
def validate_positive(positive,epoch_sha):
 keys={'schema','epoch_sha256','probe_source_sha256','unit','pid','invocation_id','start_monotonic_us','stdout_sha256','stage','positive_old_count','direct_discovery','direct_reused','ingress_reused','hold','queued','probe_active','no_job'}
 require(set(positive)==keys and type(positive['schema']) is int and positive['schema']==1 and positive['epoch_sha256']==epoch_sha and positive['probe_source_sha256']==probe_v2.SHA and positive['unit']=='sfactory-unix-admin-h2-canary-ingress-probe.service' and positive['stage']=='before_retirement' and positive['positive_old_count']==1 and positive['direct_discovery'] is True and positive['direct_reused'] is True and positive['ingress_reused'] is True and positive['probe_active'] is True and positive['no_job'] is True and isinstance(positive['stdout_sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',positive['stdout_sha256']) and isinstance(positive['hold'],str) and isinstance(positive['queued'],str) and 1<=len(positive['hold'])<=256 and 1<=len(positive['queued'])<=256 and positive['hold'].isascii() and positive['hold'].isprintable() and positive['queued'].isascii() and positive['queued'].isprintable() and positive['hold']!=positive['queued'],'positive control unavailable')
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,FENCE,STOPPED)),'retirement already attempted')
 epoch=json.loads(old.read(active.DONE,0o600));require(epoch.get('fixture_retained_active') is True and epoch.get('production_data_used') is False and all(active.identity(u)==epoch['identities'][u] for u in (base.NET,base.SERVER)),'epoch unavailable');old.directory(pkg.HANDSHAKE,0,2000,0o710)
 receipt=json.loads(old.read(old.ETC/'unix-admin-h2-canary-sdk-old-start-complete.json',0o600));require(receipt.get('unit')==pkg.OLD and receipt.get('registration') is False and receipt.get('listener_ready') is True,'old start unavailable')
 p=active.properties(pkg.OLD);require(p.get('ActiveState')=='active' and p.get('MainPID')==str(receipt['identity']['pid']) and old.ctl('show',pkg.OLD,'-p','InvocationID','--value')==receipt['identity']['invocation_id'] and p.get('Job','')=='' and p.get('ControlGroup')=='/system.slice/'+pkg.OLD,'old identity changed')
 cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/pkg.OLD).stat();require((cg.st_dev,cg.st_ino)==(receipt['identity']['cgroup_dev'],receipt['identity']['cgroup_ino']),'old cgroup changed')
 registration=json.loads(old.read(old.ETC/'unix-admin-h2-canary-register-old-complete.json',0o600));require(registration.get('operation')=='register-old' and registration.get('service_name')=='FenceFixture','old registration unavailable')
 positive=json.loads(old.read(old.ETC/'unix-admin-h2-canary-before-retirement.json',0o600));validate_positive(positive,base.sha(old.read(old.ETC/'unix-admin-h2-canary-activation-complete.json',0o600)))
 probe=active.properties(positive['unit']);require(probe.get('ActiveState')=='active' and probe.get('MainPID')==str(positive['pid']) and probe.get('Job','')=='' and old.ctl('show',positive['unit'],'-p','InvocationID','--value')==positive['invocation_id'] and old.ctl('show',positive['unit'],'-p','ExecMainStartTimestampMonotonic','--value')==str(positive['start_monotonic_us']),'positive probe no longer live')
 baseline=json.loads(old.read(old.ETC/'unix-admin-h2-canary-snapshot-baseline-complete.json',0o600, maxsize=196608));require(baseline.get('schema')==1 and baseline.get('role')=='baseline' and baseline.get('epoch_sha256')==positive['epoch_sha256'] and isinstance(baseline.get('result'),dict) and baseline['result'].get('operation')=='snapshot','baseline snapshot unavailable')
 classified=json.loads(old.read(old.ETC/'unix-admin-h2-canary-before-journal.json',0o600));require(set(classified)=={'schema','epoch_sha256','old_deployment_id','probe_receipt_sha256','snapshot_sha256','classification'} and type(classified['schema']) is int and classified['schema']==1 and classified['epoch_sha256']==positive['epoch_sha256'] and classified['old_deployment_id']==registration['deployment_id'] and classified['probe_receipt_sha256']==base.sha(old.read(old.ETC/'unix-admin-h2-canary-before-retirement.json',0o600)) and classified['snapshot_sha256']==base.sha(old.read(old.ETC/'unix-admin-h2-canary-snapshot-baseline-complete.json',0o600,maxsize=196608)) and classified['classification']=={'hold':'old-pinned-nonterminal','queued':'retained-nonterminal','delayed':'scheduled','all_drained':False},'baseline classification unavailable')
 require(old.ctl('show',CHECK,'-p','LoadState','--value')=='not-found','check unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=CHECK.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
 for root in map(pathlib.Path,paths):
  for pth in [root/CHECK,root/(CHECK+'.d'),root/'service.d']+[root/(x+'.service.d') for x in prefixes]:require(not os.path.lexists(pth),'unit collision')
 return {'schema':1,'unit':pkg.OLD,'pid':receipt['identity']['pid'],'invocation_id':receipt['identity']['invocation_id'],'cgroup_dev':cg.st_dev,'cgroup_ino':cg.st_ino,'deployment_id':registration['deployment_id'],'check_unit':CHECK,'scope':'fence and stop only disposable old SDK; preserve all data'}
def marker(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  os.fchown(fd,0,2000);os.fchmod(fd,0o440);s=os.fstat(fd);require((s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2000,1,0o440),'marker identity');old.noacl(fd);require(os.write(fd,data)==len(data),'short marker');os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(pkg.HANDSHAKE)
def apply(approved):
 require(plan()==approved,'retirement plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);marker(FENCE,b'retired\n')
 p=active.properties(pkg.OLD);cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/pkg.OLD).stat();require(p.get('ActiveState')=='active' and p.get('MainPID')==str(approved['pid']) and p.get('Job','')=='' and old.ctl('show',pkg.OLD,'-p','InvocationID','--value')==approved['invocation_id'] and (cg.st_dev,cg.st_ino)==(approved['cgroup_dev'],approved['cgroup_ino']),'old identity changed before stop');old.ctl('stop',pkg.OLD)
 p=active.properties(pkg.OLD);require(p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('ControlGroup','')=='','old stop unknown')
 cg=pathlib.Path('/sys/fs/cgroup/system.slice')/pkg.OLD
 if cg.exists():
  s=cg.stat();require((s.st_dev,s.st_ino)==(approved['cgroup_dev'],approved['cgroup_ino']),'cgroup changed');events=dict(x.split() for x in (cg/'cgroup.events').read_text().splitlines());require(events.get('populated')=='0','cgroup populated')
 code="import socket;s=socket.socket();s.settimeout(2)\ntry:s.connect(('127.0.0.1',9081))\nexcept ConnectionRefusedError:pass\nelse:raise RuntimeError('listener alive')\nfinally:s.close()\nfor p in ('/proc/self/net/tcp','/proc/self/net/tcp6'):\n for line in open(p).read().splitlines()[1:]:\n  f=line.split()\n  if f[1].rsplit(':',1)[1].upper()=='2379' and f[3]=='0A':raise RuntimeError('listener alive')\nprint('CLOSED')"
 argv=['/usr/bin/systemd-run','--unit='+CHECK,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',code]
 r=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=30,check=False);require(r.returncode==0 and r.stdout==b'CLOSED\n' and len(r.stderr)<4096,'listener closure unknown');require(old.ctl('show',CHECK,'-p','MainPID','--value')=='0' and old.ctl('show',CHECK,'-p','Job','--value')=='','closure probe not terminal')
 old.ctl('start',pkg.OLD);p=active.properties(pkg.OLD);condition=old.ctl('show',pkg.OLD,'-p','ConditionResult','--value');require(condition=='no' and p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='','restart refusal unknown')
 marker(STOPPED,b'stopped\n');result={'schema':1,'unit':pkg.OLD,'deployment_id':approved['deployment_id'],'restart_refused':True,'listener_closed':True,'old_unavailable':True};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
