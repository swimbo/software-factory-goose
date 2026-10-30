"""Quiescent versioned writer-module upgrade; no service starts or grants."""
import hashlib,json,os,pathlib,re
import nuc_grant_sidecar_install as old
import nuc_relay_package_install as pkg
import nuc_callback_package_upgrade as prior
ROOT=old.ETC;MODULE=old.PREFIX/'relay'/'nuc_root_writer_service.py';MANIFEST=ROOT/'relay-package.json';HM=ROOT/'root-launch-host.json'
INTENT=ROOT/'writer-upgrade-started.json';DONE=ROOT/'writer-upgrade-complete.json';BACKUP=ROOT/'writer-upgrade-backup-v1'
OLD_MODULE='4defa9d5566a8bcf987b17c9a5c910064a525b131618a4c37bdb26e9308eda39';NEW_MODULE='0e9f0bf575a26218b150d0bc67adb1124caf18e4fe7496411c802d67f0f7e842';SOURCE=b''

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def files():
 d=dict(pkg.PINS);d['nuc_relay_systemd.py']=prior.NEW_MODULE;return d
def producers():
 out=old.ctl('list-units','--all','--plain','--no-legend','--no-pager','sfactorywriter*.service','sfactoryrelay*.service')
 units=sorted(line.split()[0] for line in out.splitlines() if line.strip())
 for unit in units:
  require(re.fullmatch(r'sfactory(?:writer|relay)[0-9a-z]{26}\.service',unit) is not None,'unexpected producer')
  require(old.ctl('show',unit,'-p','MainPID','--value')=='0' and old.ctl('show',unit,'-p','ActiveState','--value') in ('inactive','failed') and not old.ctl('show',unit,'-p','Job','--value') and not old.ctl('show',unit,'-p','ControlGroup','--value'),'writer or relay producer active')
 return units
def snapshot():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (INTENT,DONE,BACKUP)),'upgrade attempted')
 require(hashlib.sha256(SOURCE).hexdigest()==NEW_MODULE,'new source digest mismatch')
 old.directory(ROOT,0,0,0o711);old.directory(MODULE.parent,0,0,0o755)
 module=old.read(MODULE,0o444,OLD_MODULE,1_000_000);manifest=old.read(MANIFEST,0o600);helper=old.read(HM,0o600);boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 require(json.loads(manifest)=={'schema':1,'files':files()} and json.loads(helper)=={'schema':1,'boot_id':boot,'helper_sha256':prior.NEW_HELPER},'old manifests changed')
 old.read(prior.BIN,0o755,prior.NEW_HELPER,1_000_000)
 for name,sha in files().items():old.read(MODULE.parent/name,0o444,sha,1_000_000)
 gens=prior.generations();units=prior.quiescent();others=producers()
 g='01M65RMR3F04YB1B016EBBSXGG';receipt=json.loads(old.read(prior.STATE/(g+'.failed-reconcile-complete.json'),0o600))
 require(receipt.get('generation')==g and receipt.get('kernel_closed_frozen_empty') is True and receipt.get('exact_ids_removed') is True and receipt.get('slice_retained_frozen') is True and receipt.get('engine_reconciled_for_exact_ids') is True,'failed cleanup not verified')
 cat=json.loads(old.read(ROOT/'tasks'/(g+'.json'),0o600));cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+g.lower()+'.slice');st=os.stat(cg);events=(cg/'cgroup.events').read_text().splitlines()
 require((st.st_dev,st.st_ino)==(cat.get('cgroup_dev'),cat.get('cgroup_ino')) and events.count('populated 0')==1 and events.count('frozen 1')==1 and (cg/'cgroup.freeze').read_text().strip()=='1','retained cgroup changed')
 return {'boot_id':boot,'generations':gens,'terminal_launch_units':units,'terminal_other_producers':others,'old_module_sha256':hashlib.sha256(module).hexdigest(),'old_manifest_sha256':hashlib.sha256(manifest).hexdigest(),'new_module_sha256':NEW_MODULE,'helper_sha256':prior.NEW_HELPER,'scope':'quiescent root writer code update; no service start, grant or engine effect'}
def plan():
 gens=prior.generations()
 with prior.locks(gens):
  value=snapshot();require(value['generations']==gens,'catalog changed');return value
def apply(approved):
 gens=prior.generations()
 with prior.locks(gens):
  require(snapshot()==approved and gens==approved['generations'],'upgrade plan changed')
  old.store(INTENT,prior.canon(approved)+b'\n',0o600);os.mkdir(BACKUP,0o700);old.syncdir(ROOT);old.directory(BACKUP,0,0,0o700)
  old.store(BACKUP/'module',old.read(MODULE,0o444,OLD_MODULE,1_000_000),0o600);old.store(BACKUP/'manifest',old.read(MANIFEST,0o600,approved['old_manifest_sha256']),0o600)
  require(prior.generations()==gens and prior.quiescent()==approved['terminal_launch_units'] and producers()==approved['terminal_other_producers'],'launch state changed')
  prior.atomic(MODULE,SOURCE,0o444)
  target=files();target['nuc_root_writer_service.py']=NEW_MODULE
  prior.atomic(MANIFEST,prior.canon({'schema':1,'files':target})+b'\n',0o600)
  old.read(MODULE,0o444,NEW_MODULE,1_000_000)
  require(prior.generations()==gens and prior.quiescent()==approved['terminal_launch_units'] and producers()==approved['terminal_other_producers'],'launch state changed')
  result={'boot_id':approved['boot_id'],'writer_sha256':NEW_MODULE,'backups_preserved':True,'grant_requested':False,'engine_effects':False}
  old.store(DONE,prior.canon(result)+b'\n',0o600);return result
