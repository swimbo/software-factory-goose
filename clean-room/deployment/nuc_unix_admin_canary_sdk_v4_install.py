"""Create-only replacement fixture SDK version; retains failed v3 evidence."""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_unix_admin_canary_sdk_install as prior
SRC=pathlib.Path('/tmp/sfactory-ingress-sdk-20261030/ingress-fence-sdk-v4.stripped')
SHA='3756d5cbe5f4bb3dfc4a735cc45b30cdff076f2d812ef3f57ea7bea2952dc611'
BIN=old.PREFIX/'unix-admin-canary-sdk-v4';OLD='sfactory-unix-admin-canary-sdk-v4-old.service';NEW='sfactory-unix-admin-canary-sdk-v4-new.service'
BIN_SHA=SHA;HANDSHAKE=prior.HANDSHAKE;OPS=prior.OPS;OPS_SHA=prior.OPS_SHA;PROBE=prior.PROBE
sha=prior.sha
START=old.ETC/'unix-admin-canary-sdk-v4-install-started.json';DONE=old.ETC/'unix-admin-canary-sdk-v4-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def units():
 out={}
 for oldname,newname,role in ((prior.OLD,OLD,'old'),(prior.NEW,NEW,'new')):
  text=prior.units()[oldname].decode().replace(str(prior.BIN),str(BIN)).replace('sdk-'+role+'.log','sdk-v4-'+role+'.log');out[newname]=text.encode()
 return out
def plan():
 require(os.geteuid()==0 and isinstance(SHA,str) and len(SHA)==64,'candidate unavailable');require(not any(os.path.lexists(p) for p in (START,DONE,BIN,prior.HANDSHAKE/'sdk-v4-old.log',prior.HANDSHAKE/'sdk-v4-new.log')),'destination occupied')
 receipt=json.loads(old.read(prior.DONE,0o600));require(receipt=={'installed':True,'started':False,'registration':False},'v3 package unavailable');old.directory(prior.HANDSHAKE,0,2000,0o710);old.directory(SRC.parent,1000,1000,0o700)
 require(not any(os.path.lexists(prior.HANDSHAKE/name) for name in ('old.retired','old.stopped')),'retirement already begun')
 old.read(prior.BIN,0o755,prior.BIN_SHA,40_000_000)
 for name in (prior.OLD,prior.NEW):
  old.read(old.UNIT/name,0o644,prior.sha(prior.units()[name]));p=active.properties(name);require(p.get('ActiveState') in ('inactive','failed') and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='','v3 SDK not inactive')
 for name in (base.NET,base.SERVER):require(active.properties(name).get('ActiveState')=='active','fixture unavailable')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in units():
  require(not os.path.lexists(old.UNIT/name) and old.ctl('show',name,'-p','LoadState','--value')=='not-found','unit occupied');stem=name.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
  for parent in map(pathlib.Path,paths):
   for p in [parent/name,parent/(name+'.d'),parent/'service.d']+[parent/(x+'.service.d') for x in prefixes]:require(not os.path.lexists(p),'unit collision')
 return {'source':prior.candidate(SRC,SHA,0o755,40_000_000),'units':{n:prior.sha(v) for n,v in units().items()},'scope':'create-only versioned v4 SDK; retain v3 files; no start or registration'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,base.canonical(approved)+b'\n',0o600);require(prior.candidate(SRC,SHA,0o755,40_000_000,BIN)==approved['source'],'candidate changed');old.syncdir(old.PREFIX)
 for role in ('old','new'):
  fd=os.open(prior.HANDSHAKE/('sdk-v4-'+role+'.log'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  try:os.fchown(fd,0,2000);os.fchmod(fd,0o620);old.noacl(fd);os.fsync(fd)
  finally:os.close(fd)
 old.syncdir(prior.HANDSHAKE)
 for name,data in units().items():old.store(old.UNIT/name,data,0o644)
 old.ctl('daemon-reload')
 for name in units():
  p=active.properties(name);require(p.get('LoadState')=='loaded' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='' and p.get('Job','')=='','v4 unit unavailable')
 result={'installed':True,'started':False,'registration':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
