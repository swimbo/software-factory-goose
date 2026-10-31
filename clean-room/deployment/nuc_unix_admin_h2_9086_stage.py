"""Fixed separate 9086 synthetic start, prezero, one dispatch and observation."""
import hashlib,json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as active
import nuc_unix_admin_h2_sdk_start as epochcheck
import nuc_unix_admin_h2_9086_install as sdk
import nuc_unix_admin_h2_9086_helpers_install as helpers
ROLE=None
def require(v,m):
 if not v:raise RuntimeError(m)
def names():
 require(ROLE in ('start','prezero','dispatch','reconcile'),'role unavailable');return old.ETC/('unix-admin-h2-canary-9086-'+ROLE+'-started.json'),old.ETC/('unix-admin-h2-canary-9086-'+ROLE+'-complete.json'),'sfactory-unix-admin-h2-9086-'+ROLE+'.service'
def plan():
 started,done,unit=names();require(os.geteuid()==0 and not os.path.lexists(started) and not os.path.lexists(done),'stage already attempted')
 require(json.loads(old.read(sdk.DONE,0o600))=={'schema':1,'installed':True,'started':False,'registration':False} and json.loads(old.read(helpers.DONE,0o600))=={'schema':1,'installed':True,'executed':False},'package unavailable')
 require(json.loads(old.read(old.ETC/'unix-admin-h2-canary-register-new-unknown.json',0o600)).get('no_retry') is True,'9082 unknown unavailable')
 er=old.read(old.ETC/'unix-admin-h2-canary-epoch3-complete.json',0o600);epoch=json.loads(er);epochcheck.verify_epoch(epoch)
 for path in (base.HANDSHAKE/'old.retired',base.HANDSHAKE/'old.stopped'):require(os.path.lexists(path),'old fence unavailable')
 old.read(sdk.BIN,0o755,sdk.SHA,40_000_000);old.read(old.UNIT/sdk.UNIT,0o644,base.sha(sdk.unit()));old.read(helpers.QUERY,0o755,helpers.QUERY_SHA);old.read(helpers.LOST,0o755,helpers.LOST_SHA)
 p=active.properties(sdk.UNIT)
 if ROLE=='start':require(p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='','9086 unit not inactive')
 else:
  start=json.loads(old.read(old.ETC/'unix-admin-h2-canary-9086-start-complete.json',0o600));require(active.identity(sdk.UNIT)==start['identity'],'9086 identity changed')
 if ROLE in ('dispatch','reconcile'):
  zero=json.loads(old.read(old.ETC/'unix-admin-h2-canary-9086-prezero-complete.json',0o600));require(zero.get('epoch_sha256')==base.sha(er) and zero.get('result')=={'schema':1,'operation':'new-uri-matches','ids':[]},'prezero unavailable')
 if ROLE=='reconcile':require(json.loads(old.read(old.ETC/'unix-admin-h2-canary-9086-dispatch-complete.json',0o600))=={'schema':1,'stage':'response_unknown','one_dispatch':True,'no_retry':True},'dispatch unavailable')
 require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','unit occupied');roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit paths unavailable');stem=unit.removesuffix('.service')
 for root in map(pathlib.Path,roots):
  for n in [unit,unit+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/n),'unit collision')
 return {'schema':1,'role':ROLE,'epoch_sha256':base.sha(er),'unit':unit,'scope':'one fixed synthetic 9086 stage; 9082 remains unknown'}
def apply(approved):
 require(plan()==approved,'stage changed');started,done,unit=names();old.store(started,base.canonical(approved)+b'\n',0o600)
 if ROLE=='start':
  old.ctl('start',sdk.UNIT);identity=active.identity(sdk.UNIT);fields={k:v.split() for k,v in (x.split(':',1) for x in pathlib.Path('/proc',str(identity['pid']),'status').read_text().splitlines() if ':' in x)}
  require(fields.get('Uid')==['2000']*4 and fields.get('Gid')==['2000']*4 and fields.get('NoNewPrivs')==['1'] and all(fields.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')),'SDK credentials unavailable')
  code="import os\nif (os.getuid(),os.geteuid(),os.getgid(),os.getegid())!=(2000,2000,2000,2000):raise RuntimeError('identity')\nd=dict(x.split(':',1) for x in open('/proc/self/status').read().splitlines() if ':' in x)\nif d.get('NoNewPrivs','').strip()!='1' or any(int(d.get('Cap'+n,'1').strip(),16) for n in ('Inh','Prm','Eff','Bnd','Amb')):raise RuntimeError('privileges')\nos.execv('/usr/bin/curl',['curl','--disable','--silent','--show-error','--fail','--max-time','5','--max-filesize','65536','--http2-prior-knowledge','--noproxy','*','-H','Accept: application/vnd.restate.endpointmanifest.v4+json','http://127.0.0.1:9086/discover'])"
  args=['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=15s','/usr/bin/python3','-I','-B','-c',code]
  p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=25,check=False);require(p.returncode==0 and len(p.stdout)<=65536 and len(p.stderr)<=8192,'SDK readiness unknown');manifest=json.loads(p.stdout);require(isinstance(manifest,dict) and isinstance(manifest.get('services'),list) and any(isinstance(x,dict) and x.get('name')=='FenceFixture' for x in manifest['services']),'SDK manifest unavailable');require(old.ctl('show',unit,'-p','MainPID','--value')=='0' and old.ctl('show',unit,'-p','Job','--value')=='' and active.identity(sdk.UNIT)==identity,'SDK readiness unresolved')
  result={'schema':1,'epoch_sha256':approved['epoch_sha256'],'identity':identity,'discovery_h2':True};old.store(done,base.canonical(result)+b'\n',0o600);return result
 command=[str(helpers.LOST)] if ROLE=='dispatch' else [str(helpers.QUERY),'new-uri-matches']
 args=['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=25s','/usr/bin/python3','-I','-B']+command
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=35,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=8192,'stage outcome unknown');require(old.ctl('show',unit,'-p','MainPID','--value')=='0' and old.ctl('show',unit,'-p','Job','--value')=='','stage unresolved')
 if ROLE=='dispatch':require(p.stdout==b'DISPATCHED_RESPONSE_UNKNOWN\n','dispatch unknown');result={'schema':1,'stage':'response_unknown','one_dispatch':True,'no_retry':True}
 else:
  out=json.loads(p.stdout);require(set(out)=={'schema','operation','ids'} and out['schema']==1 and out['operation']=='new-uri-matches' and isinstance(out['ids'],list) and all(isinstance(x,str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',x) for x in out['ids']) and len(out['ids'])==(0 if ROLE=='prezero' else 1),'URI outcome unresolved');result={'schema':1,'role':ROLE,'epoch_sha256':approved['epoch_sha256'],'result':out}
 old.store(done,base.canonical(result)+b'\n',0o600);return result
