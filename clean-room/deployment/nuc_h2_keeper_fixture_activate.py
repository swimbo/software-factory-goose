"""One-shot activation of only the installed isolated H2 control fixture."""
import json,os,pathlib
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_h2_keeper_fixture_install as fixture
START=old.ETC/'h2-keeper-canary-activate-started.json';NET_STARTED=old.ETC/'h2-keeper-canary-net-started.json';SDK_STARTED=old.ETC/'h2-keeper-canary-sdk-started.json';DONE=old.ETC/'h2-keeper-canary-activate-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,NET_STARTED,SDK_STARTED,DONE)),'activation already attempted')
 require(json.loads(old.read(fixture.DONE,0o600))=={'schema':1,'installed':True,'started':False,'registration':False},'install receipt unavailable')
 old.directory(fixture.ROOT,0,0,0o711);old.directory(fixture.HANDSHAKE,0,2000,0o710)
 old.read(fixture.sdk.BIN,0o755,fixture.sdk.SHA,40_000_000)
 for name,data in fixture.units().items():
  old.read(old.UNIT/name,0o644,base.sha(data));p=active.properties(name)
  require(p.get('LoadState')=='loaded' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='','unit not ready')
 return {'schema':1,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'binary_sha256':fixture.sdk.SHA,'units':{name:base.sha(data) for name,data in fixture.units().items()},'scope':'start only owned isolated H2 network and fixed toy SDK; no Restate'}
def identity(name):
 p=active.properties(name);pid=int(p.get('MainPID','0'));require(p.get('ActiveState')=='active' and pid>0 and p.get('Job','')=='' and p.get('Names')==name,'unit outcome unknown')
 invocation=old.ctl('show',name,'-p','InvocationID','--value');require(len(invocation)==32,'invocation unavailable')
 ticks=int(pathlib.Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]);cg=(pathlib.Path('/sys/fs/cgroup/system.slice')/name).stat()
 return {'pid':pid,'invocation_id':invocation,'start_ticks':ticks,'cgroup_dev':cg.st_dev,'cgroup_ino':cg.st_ino}
def apply(approved):
 require(plan()==approved,'activation plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 old.store(NET_STARTED,base.canonical({'schema':1,'unit':fixture.NET})+b'\n',0o600);old.ctl('start',fixture.NET);net=identity(fixture.NET)
 old.store(SDK_STARTED,base.canonical({'schema':1,'unit':fixture.SDK})+b'\n',0o600);old.ctl('start',fixture.SDK);sdk=identity(fixture.SDK)
 require(identity(fixture.NET)==net,'network identity changed')
 result={'schema':1,'boot_id':approved['boot_id'],'identities':{fixture.NET:net,fixture.SDK:sdk},'sdk_binary_sha256':fixture.sdk.SHA,'registration':False,'fixture_retained_active':True}
 old.store(DONE,base.canonical(result)+b'\n',0o600);return result
