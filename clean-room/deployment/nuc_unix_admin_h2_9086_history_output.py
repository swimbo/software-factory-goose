"""Fixed, bounded read-only synthetic history output observation."""
import hashlib,json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_sdk_start as sdk
SOURCE=None;SOURCE_SHA='4220bbdb914bec7d58cb54df88f8eee9e3c5837c70494c45c5587ed3064f44c4'
BIN=old.PREFIX/'unix-admin-h2-canary-history-output.py';INSTALL_START=old.ETC/'unix-admin-h2-canary-history-output-install-started.json';INSTALL_DONE=old.ETC/'unix-admin-h2-canary-history-output-install-complete.json';ROLE=None
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and ROLE in ('install','baseline','afterrestart'),'role unavailable')
 if ROLE=='install':
  require(isinstance(SOURCE,bytes) and base.sha(SOURCE)==SOURCE_SHA and not any(os.path.lexists(p) for p in (BIN,INSTALL_START,INSTALL_DONE)),'source unavailable');return {'schema':1,'role':ROLE,'source_sha256':SOURCE_SHA,'scope':'install fixed read-only history helper'}
 started=old.ETC/('unix-admin-h2-canary-history-output-'+ROLE+'-started.json');done=old.ETC/('unix-admin-h2-canary-history-output-'+ROLE+'.json');require(not os.path.lexists(started) and not os.path.lexists(done),'history observation occupied')
 require(json.loads(old.read(INSTALL_DONE,0o600))=={'schema':1,'installed':True,'executed':False,'source_sha256':SOURCE_SHA},'install unavailable');old.read(BIN,0o755,SOURCE_SHA)
 snapraw=old.read(old.ETC/('unix-admin-h2-canary-snapshot-'+ROLE+'-complete.json'),0o600,maxsize=196608);snap=json.loads(snapraw);require(snap.get('role')==ROLE and snap.get('result',{}).get('operation')=='snapshot','snapshot unavailable')
 if ROLE=='afterrestart':
  epoch_raw=old.read(old.ETC/'unix-admin-h2-canary-9086-restate-restart-complete.json',0o600);restart=json.loads(epoch_raw);require(restart.get('old_restart_refused') is True and restart.get('history_replayed') is False,'restart unavailable');epoch=restart['epoch3'];sdk.verify_epoch(epoch,allow_registered=True)
 else:
  epoch_raw=old.read(sdk.active.DONE,0o600);epoch=json.loads(epoch_raw);sdk.verify_epoch(epoch)
 require(snap.get('epoch_sha256')==base.sha(epoch_raw),'epoch mismatch')
 rows=snap['result']['rows']['invocations'];matches=[x for x in rows if x.get('target_service_name')=='FenceFixture' and x.get('target_service_key')=='history' and x.get('target_handler_name')=='increment'];require(len(matches)==1 and matches[0].get('status')=='completed' and matches[0].get('completion_result')=='success' and matches[0].get('pinned_deployment_id')==json.loads(old.read(old.ETC/'unix-admin-h2-canary-register-old-complete.json',0o600)).get('deployment_id'),'history unavailable');identity=matches[0].get('id');require(isinstance(identity,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,256}',identity),'identity unavailable')
 unit='sfactory-unix-admin-h2-history-output-'+ROLE+'.service';require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','unit occupied')
 roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable');stem=unit.removesuffix('.service')
 for root in map(pathlib.Path,roots):
  for n in [unit,unit+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/n),'unit collision')
 return {'schema':1,'role':ROLE,'epoch_sha256':base.sha(epoch_raw),'snapshot_sha256':base.sha(snapraw),'invocation_sha256':hashlib.sha256(identity.encode()).hexdigest(),'unit':unit,'scope':'one fixed read-only output observation'}
def apply(approved):
 require(plan()==approved,'history plan changed')
 if ROLE=='install':
  old.store(INSTALL_START,base.canonical(approved)+b'\n',0o600);old.store(BIN,SOURCE,0o755);old.read(BIN,0o755,SOURCE_SHA);result={'schema':1,'installed':True,'executed':False,'source_sha256':SOURCE_SHA};old.store(INSTALL_DONE,base.canonical(result)+b'\n',0o600);return result
 started=old.ETC/('unix-admin-h2-canary-history-output-'+ROLE+'-started.json');done=old.ETC/('unix-admin-h2-canary-history-output-'+ROLE+'.json');old.store(started,base.canonical(approved)+b'\n',0o600)
 s=json.loads(old.read(old.ETC/('unix-admin-h2-canary-snapshot-'+ROLE+'-complete.json'),0o600,maxsize=196608));identity=next(x['id'] for x in s['result']['rows']['invocations'] if x.get('target_service_name')=='FenceFixture' and x.get('target_service_key')=='history' and x.get('target_handler_name')=='increment');require(hashlib.sha256(identity.encode()).hexdigest()==approved['invocation_sha256'],'identity changed')
 args=['/usr/bin/systemd-run','--unit='+approved['unit'],'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B',str(BIN)]
 p=subprocess.run(args,input=(identity+'\n').encode(),env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and len(p.stdout)<=1024 and len(p.stderr)<=4096,'history observation unknown');obs=json.loads(p.stdout);require(obs.get('schema')==1 and obs.get('invocation_sha256')==approved['invocation_sha256'] and obs.get('expected_response') is True and obs.get('read_only') is True and re.fullmatch(r'[0-9a-f]{64}',obs.get('output_sha256','')),'history result unavailable');require(old.ctl('show',approved['unit'],'-p','MainPID','--value')=='0' and old.ctl('show',approved['unit'],'-p','Job','--value')=='','history probe unresolved')
 result={'schema':1,'role':ROLE,'epoch_sha256':approved['epoch_sha256'],'snapshot_sha256':approved['snapshot_sha256'],'invocation_sha256':approved['invocation_sha256'],'output_sha256':obs['output_sha256'],'expected_response':True,'read_only':True};old.store(done,base.canonical(result)+b'\n',0o600);return result
