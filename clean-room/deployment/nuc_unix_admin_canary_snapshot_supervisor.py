"""Root supervised fixed, bounded synthetic journal observation."""
import json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_start_v4_old as start
import nuc_unix_admin_canary_snapshot_install as installed
ROLE=None
ACTIONS={'baseline':'snapshot','postretire':'snapshot','afterrestart':'snapshot','prezero-old':'old-uri-matches','prezero':'new-uri-matches','reconcile':'new-uri-matches'}
def require(v,m):
 if not v:raise RuntimeError(m)
def files(role):return (old.ETC/('unix-admin-canary-snapshot-'+role+'-started.json'),old.ETC/('unix-admin-canary-snapshot-'+role+'-complete.json'))
def unit(role):return 'sfactory-unix-admin-snapshot-'+role+'.service'
def plan():
 role=ROLE;require(os.geteuid()==0 and role in ACTIONS,'fixed role unavailable');started,complete=files(role);require(not os.path.lexists(started) and not os.path.lexists(complete),'snapshot already attempted')
 receipt=json.loads(old.read(installed.DONE,0o600));require(receipt=={'installed':True,'queried':False},'snapshot package unavailable');old.read(installed.DEST,0o755,installed.OPS_SHA)
 if role=='afterrestart':
  epoch_raw=old.read(old.ETC/'unix-admin-canary-restate-restart-complete.json',0o600);restart=json.loads(epoch_raw);require(restart.get('old_restart_refused') is True and restart.get('history_replayed') is False,'restart receipt unavailable');epoch=restart['epoch3'];start.verify_epoch(epoch,allow_registered=True)
 else:
  epoch_raw=old.read(old.ETC/'unix-admin-canary-epoch2-complete.json',0o600);epoch=json.loads(epoch_raw);start.verify_epoch(epoch)
 require(epoch['boot_id']==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'epoch boot changed')
 if role in ('baseline','prezero'):require(os.path.lexists(old.ETC/'unix-admin-canary-v4-register-old-complete.json'),'old registration unavailable')
 if role in ('postretire','prezero','reconcile','afterrestart'):require(os.path.lexists(old.ETC/'unix-admin-canary-v4-retirement-complete.json'),'retirement unavailable')
 if role=='reconcile':require(os.path.lexists(old.ETC/'unix-admin-canary-v4-register-new-started.json'),'new registration not attempted')
 name=unit(role);require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','snapshot unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=name.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
 for root in map(pathlib.Path,paths):
  for p in [root/name,root/(name+'.d'),root/'service.d']+[root/(x+'.service.d') for x in prefixes]:require(not os.path.lexists(p),'unit collision')
 return {'schema':1,'role':role,'action':ACTIONS[role],'unit':name,'epoch_sha256':base.sha(epoch_raw),'source_sha256':installed.OPS_SHA,'scope':'read-only fixed synthetic admin query; no caller SQL'}
def apply(approved):
 require(plan()==approved,'snapshot plan changed');role=ROLE;started,complete=files(role);old.store(started,base.canonical(approved)+b'\n',0o600)
 argv=['/usr/bin/systemd-run','--unit='+unit(role),'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=128M','--property=TasksMax=32','--property=RuntimeMaxSec=35s','/usr/bin/python3','-I','-B',str(installed.DEST),ACTIONS[role]]
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=45,check=False);require(p.returncode==0 and len(p.stdout)<=196608 and len(p.stderr)<=8192,'snapshot outcome unknown');out=json.loads(p.stdout)
 require(isinstance(out,dict) and out.get('schema')==1 and out.get('operation')==ACTIONS[role],'snapshot response unavailable')
 if role in ('prezero-old','prezero'):require(set(out)=={'schema','operation','ids'} and out['ids']==[],'URI already exists or ambiguous')
 if role=='reconcile':require(set(out)=={'schema','operation','ids'} and isinstance(out['ids'],list) and len(out['ids'])==1 and isinstance(out['ids'][0],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',out['ids'][0]),'new URI outcome unresolved')
 require(old.ctl('show',unit(role),'-p','MainPID','--value')=='0' and old.ctl('show',unit(role),'-p','Job','--value')=='','snapshot process unresolved')
 raw=base.canonical({'schema':1,'role':role,'epoch_sha256':approved['epoch_sha256'],'result':out})+b'\n';old.store(complete,raw,0o600);return {'schema':1,'role':role,'receipt_sha256':base.sha(raw),'read_only':True}
