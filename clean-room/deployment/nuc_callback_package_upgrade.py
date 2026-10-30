"""Quiescent create-intent upgrade of fixed root-owned factory callback code."""
import contextlib,fcntl,hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
import nuc_relay_package_install as pkg
ROOT=old.ETC;STATE=pathlib.Path('/var/lib/software-factory-goose/stop');CAT=ROOT/'launch-catalog';BIN=old.PREFIX/'root-launch-host.py';MODULE=old.PREFIX/'relay'/'nuc_relay_systemd.py';PM=ROOT/'relay-package.json';HM=ROOT/'root-launch-host.json'
INTENT=ROOT/'callback-upgrade-started.json';DONE=ROOT/'callback-upgrade-complete.json';BACKUP=ROOT/'callback-upgrade-backup-v1'
OLD_HELPER='3de11eef342e32c98c2d87659d647fc33547048b7ea80699e3bf117ec5d9a06d';NEW_HELPER='604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e'
OLD_MODULE='ea16c500e2f2f7786210801d22802be6e8736217e39933133da466e3a1312031';NEW_MODULE='e99c1f9580c473f9c91a3f31cb6445db98e6420d07d306088c05d3da9d6c0dcf'
ID=re.compile(r'[0-7][0-9A-HJKMNP-TV-Z]{25}\Z');HELPER_SOURCE=b'';MODULE_SOURCE=b''

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def sha(x):return hashlib.sha256(x).hexdigest()
def generations():
 old.directory(CAT,0,0,0o700);old.directory(STATE,0,0,0o700)
 gens=sorted(p.name[:-5] for p in CAT.iterdir() if ID.fullmatch(p.name[:-5]) and p.name.endswith('.json'))
 require(gens,'no launch catalogs')
 for g in gens:
  c=json.loads(old.read(CAT/(g+'.json'),0o600));require(c['scope']['generation']==g,'catalog generation mismatch')
  require(old.read(STATE/(g+'.closed'),0o600)==(g+'\n').encode(),'open catalog prevents upgrade')
 return gens
@contextlib.contextmanager
def locks(gens):
 held=[]
 try:
  for g in gens:
   for suffix in ('.lock','.callback-lifecycle.lock'):
    path=STATE/(g+suffix)
    if not os.path.lexists(path):continue
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK);held.append(fd);st=os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,0,1,0o600),'launcher lock untrusted');old.noacl(fd);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  yield
 finally:
  for fd in held:os.close(fd)
def quiescent():
 out=old.ctl('list-units','--all','--plain','--no-legend','--no-pager','sfactory-intloop-launch-*.service')
 units=[line.split()[0] for line in out.splitlines() if line.strip()]
 for name in units:
  require(re.fullmatch(r'sfactory-intloop-launch-[0-9a-z]{26}\.service',name) is not None,'unexpected launch unit')
  require(old.ctl('show',name,'-p','MainPID','--value')=='0' and old.ctl('show',name,'-p','ActiveState','--value') in ('inactive','failed') and not old.ctl('show',name,'-p','Job','--value') and not old.ctl('show',name,'-p','ControlGroup','--value'),'launcher still active or ambiguous')
 return sorted(units)
def snapshot():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (INTENT,DONE,BACKUP)),'upgrade attempted')
 require(sha(HELPER_SOURCE)==NEW_HELPER and sha(MODULE_SOURCE)==NEW_MODULE,'new source digest mismatch')
 old.directory(old.PREFIX,0,0,0o755);old.directory(MODULE.parent,0,0,0o755);old.directory(ROOT,0,0,0o711)
 helper=old.read(BIN,0o755,OLD_HELPER,1_000_000);module=old.read(MODULE,0o444,OLD_MODULE,1_000_000)
 pm=old.read(PM,0o600);hm=old.read(HM,0o600);package=json.loads(pm);host=json.loads(hm);boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 require(package=={'schema':1,'files':pkg.PINS} and host=={'schema':1,'boot_id':boot,'helper_sha256':OLD_HELPER},'old manifest mismatch')
 for name,digest in pkg.PINS.items():old.read(MODULE.parent/name,0o444,digest,1_000_000)
 gens=generations();units=quiescent()
 return {'boot_id':boot,'generations':gens,'terminal_launch_units':units,'old':{'helper':sha(helper),'module':sha(module),'package_manifest':sha(pm),'helper_manifest':sha(hm)},'new':{'helper':NEW_HELPER,'module':NEW_MODULE},'scope':'quiescent callback upgrade; no grant, service restart or engine effect'}
def plan():
 g=generations()
 with locks(g):
  x=snapshot();require(x['generations']==g,'catalog changed');return x

def atomic(path,data,mode):
 temp=path.with_name('.'+path.name+'.callback-v2.tmp')
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  os.fchmod(fd,mode);view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(path.parent);os.replace(temp,path);old.syncdir(path.parent)

def apply(approved):
 g=generations()
 with locks(g):
  require(snapshot()==approved and g==approved['generations'],'upgrade plan changed')
  old.store(INTENT,canon(approved)+b'\n',0o600)
  os.mkdir(BACKUP,0o700);old.syncdir(ROOT);old.directory(BACKUP,0,0,0o700)
  previous={name:old.read(path,mode,digest,1_000_000) for name,path,mode,digest in [('helper',BIN,0o755,approved['old']['helper']),('module',MODULE,0o444,approved['old']['module']),('package-manifest',PM,0o600,approved['old']['package_manifest']),('helper-manifest',HM,0o600,approved['old']['helper_manifest'])]}
  for name,data in previous.items():old.store(BACKUP/name,data,0o600)
  require(generations()==g and quiescent()==approved['terminal_launch_units'],'launch state changed')
  atomic(BIN,HELPER_SOURCE,0o755);atomic(MODULE,MODULE_SOURCE,0o444)
  files=dict(pkg.PINS);files['nuc_relay_systemd.py']=NEW_MODULE
  atomic(PM,canon({'schema':1,'files':files})+b'\n',0o600)
  atomic(HM,canon({'schema':1,'boot_id':approved['boot_id'],'helper_sha256':NEW_HELPER}),0o600)
  old.read(BIN,0o755,NEW_HELPER,1_000_000);old.read(MODULE,0o444,NEW_MODULE,1_000_000)
  require(generations()==g and quiescent()==approved['terminal_launch_units'],'launch state changed after upgrade')
  result={'boot_id':approved['boot_id'],'helper_sha256':NEW_HELPER,'module_sha256':NEW_MODULE,'backups_preserved':True,'grant_requested':False,'engine_effects':False}
  old.store(DONE,canon(result)+b'\n',0o600);return result
