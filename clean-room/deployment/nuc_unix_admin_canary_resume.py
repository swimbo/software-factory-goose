"""Exact create-only continuation after known pre-file mkdir/chown failure."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as install
RESUME=old.ETC/'unix-admin-canary-install-resume-started.json'
EXPECTED={str(install.ROOT):(66306,19142891),str(install.DATA):(66306,19142892)}
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(RESUME) and not os.path.lexists(install.DONE),'continuation already attempted')
 raw=old.read(install.START,0o600);before=json.loads(raw)
 require(before['scope']=='create-only files and inactive units; no service start, network change or live data' and before['config_sha256']==install.sha(install.CONF) and before['anchor_sha256']==install.sha(install.ANCHOR_SOURCE) and before['probe_sha256']==install.sha(install.PROBE_SOURCE) and before['units']=={n:install.sha(v) for n,v in install.units().items()} and install.verify_restate()==before['restate'],'original intent changed')
 for p,u,g,m in [(install.ROOT,0,0,0o711),(install.DATA,2004,2004,0o700)]:
  old.directory(p,u,g,m);s=os.lstat(p);require((s.st_dev,s.st_ino)==EXPECTED[str(p)],'fixture inode changed')
 require(not list(install.DATA.iterdir()) and {p.name for p in install.ROOT.iterdir()}=={'data'},'unexpected data')
 dest=[install.CONFIG,install.ANCHOR,install.PROBE]+[old.UNIT/name for name in install.units()];require(not any(os.path.lexists(p) for p in dest),'destination occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in install.units():
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','fixture unit occupied');stem=name.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
  for base in map(pathlib.Path,paths):
   for p in [base/name,base/(name+'.d'),base/'service.d']+[base/(prefix+'.service.d') for prefix in prefixes]:require(not os.path.lexists(p),'unit collision')
 require(old.old_snapshot()==before['old'],'existing factory changed')
 return {'original_intent_sha256':install.sha(raw),'fixture_inodes':{k:list(v) for k,v in EXPECTED.items()},'config_sha256':before['config_sha256'],'anchor_sha256':before['anchor_sha256'],'probe_sha256':before['probe_sha256'],'units':before['units'],'scope':'resume exact empty fixture; create missing files and inactive units only'}
def apply(approved):
 require(plan()==approved,'continuation plan changed');old.store(RESUME,install.canonical(approved)+b'\n',0o600)
 old.store(install.CONFIG,install.CONF,0o644);old.store(install.ANCHOR,install.ANCHOR_SOURCE,0o755);old.store(install.PROBE,install.PROBE_SOURCE,0o755)
 for name,data in install.units().items():old.store(old.UNIT/name,data,0o644)
 old.ctl('daemon-reload')
 for name in install.units():
  p=dict(line.split('=',1) for line in old.ctl('show',name,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,Job','--no-pager').splitlines())
  require(p.get('LoadState')=='loaded' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='','fixture unit identity mismatch')
 before=json.loads(old.read(install.START,0o600));require(old.old_snapshot()==before['old'],'existing factory changed')
 result={'installed':True,'started':False,'network_changed':False,'production_data_used':False};old.store(install.DONE,install.canonical(result)+b'\n',0o600);return result
