"""One read-only fixed URI observation after synthetic registration unknown."""
import hashlib,json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_sdk_start as sdk
import nuc_unix_admin_h2_helpers_install as helpers
START=old.ETC/'unix-admin-h2-canary-new-uri-diagnostic-started.json';DONE=old.ETC/'unix-admin-h2-canary-new-uri-diagnostic-complete.json';UNIT='sfactory-unix-admin-h2-new-uri-diagnostic.service'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE),'diagnostic occupied')
 prior=old.read(old.ETC/'unix-admin-h2-canary-snapshot-prezero-complete.json',0o600);p=json.loads(prior);require(p.get('role')=='prezero' and p.get('result')=={'schema':1,'operation':'new-uri-matches','ids':[]},'prezero unavailable')
 unknown=old.read(old.ETC/'unix-admin-h2-canary-register-new-unknown.json',0o600);require(json.loads(unknown)=={'schema':1,'stage':'response_unknown','one_dispatch':True,'no_retry':True},'dispatch unavailable')
 require(os.path.lexists(old.ETC/'unix-admin-h2-canary-snapshot-reconcile-started.json') and not os.path.lexists(old.ETC/'unix-admin-h2-canary-snapshot-reconcile-complete.json'),'reconcile not unresolved')
 er=old.read(old.ETC/'unix-admin-h2-canary-epoch2-complete.json',0o600);epoch=json.loads(er);sdk.verify_epoch(epoch);require(p.get('epoch_sha256')==base.sha(er),'epoch changed')
 old.read(helpers.DEST,0o755,helpers.OPS_SHA);require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied')
 roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for root in map(pathlib.Path,roots):
  for n in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/n),'unit collision')
 return {'schema':1,'epoch_sha256':base.sha(er),'prezero_sha256':base.sha(prior),'dispatch_sha256':base.sha(unknown),'unit':UNIT,'scope':'one read-only exact new-URI observation; no registration retry'}
def apply(approved):
 require(plan()==approved,'diagnostic changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=25s','/usr/bin/python3','-I','-B',str(helpers.DEST),'new-uri-matches']
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=35,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=8192,'URI observation unknown');out=json.loads(p.stdout);require(set(out)=={'schema','operation','ids'} and out['schema']==1 and out['operation']=='new-uri-matches' and isinstance(out['ids'],list) and len(out['ids'])<=1 and all(isinstance(x,str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',x) for x in out['ids']),'URI response invalid');require(old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','diagnostic unresolved')
 receipt={'schema':1,'epoch_sha256':approved['epoch_sha256'],'prezero_sha256':approved['prezero_sha256'],'dispatch_sha256':approved['dispatch_sha256'],'result':out,'no_retry':True};old.store(DONE,base.canonical(receipt)+b'\n',0o600)
 return {'schema':1,'matches':len(out['ids']),'id_sha256':hashlib.sha256(out['ids'][0].encode()).hexdigest() if out['ids'] else None,'no_retry':True,'zero_is_not_absence_proof':True}
