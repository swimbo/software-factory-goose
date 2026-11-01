"""Version one inactive SDK5 runtime fragment to require Unix-admin Restate."""
import json,os
import nuc_grant_sidecar_install as old
import nuc_registry_offline_backup as backup
import nuc_registry_retirement_coordinator as retired
import nuc_registry_transition_gate as gate
import nuc_registry_v5_guarded_install as guarded
import nuc_registry_unix_restate_provision as unix
T=retired.T;UNIT=guarded.NAME+'runtime.service';PATH=old.UNIT/UNIT;BACKUP=old.UNIT/(UNIT+'.pre-unix-'+T.lower());TEMP=old.UNIT/(UNIT+'.unix-new-'+T.lower())
START=old.ETC/('registry-v5-unix-unit-upgrade-started.json');DONE=old.ETC/('registry-v5-unix-unit-upgrade-complete.json')
def require(v,m):
 if not v:raise RuntimeError(m)
def unit():
 original=guarded.units()[UNIT];oldname='software-factory-goose-private-restate.service'.encode();newname=unix.UNIT.encode();require(original.count(oldname)==2,'prior dependency unavailable');return original.replace(oldname,newname)
def inactive():
 p=retired.properties(UNIT);require(p.get('LoadState')=='loaded' and p.get('Names')==UNIT and p.get('FragmentPath')==str(PATH) and p.get('DropInPaths','')=='' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='','SDK5 runtime not inactive')
def plan_locked():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,BACKUP,TEMP)),'SDK5 unit upgrade occupied')
 retired_raw,_=backup.retirement_state();bplan=gate._json(old.read(backup.START,0o600,maxsize=1000000));retired.terminal(backup.RESTATE,bplan['restate']);old.read(backup.FENCE,0o600,backup.sha(b'offline\n'));old.read(backup.DROP,0o644,backup.sha(backup.dropin()));backup.verify_loaded_fence(bplan['restate'])
 provision=json.loads(old.read(unix.DONE,0o600));require(provision.get('transition_id')==T and provision.get('started') is False and provision.get('unit_sha256')==backup.sha(unix.unit()) and provision.get('config_sha256')==backup.sha(unix.CONF),'Unix unit unavailable');old.read(old.UNIT/unix.UNIT,0o644,provision['unit_sha256']);old.read(unix.CONFIG,0o644,provision['config_sha256'])
 g=json.loads(old.read(guarded.DONE,0o600));require(g.get('binary_sha256')==guarded.SOURCE_SHA and g.get('installed_inactive') is True and g.get('executed') is False,'guarded runtime unavailable');old.read(guarded.BIN,0o755,guarded.SOURCE_SHA,100000000)
 original=guarded.units()[UNIT];old.read(PATH,0o644,backup.sha(original));inactive();return {'schema':1,'transition_id':T,'prior_sha256':backup.sha(original),'unit_sha256':backup.sha(unit()),'guarded_binary_sha256':guarded.SOURCE_SHA,'unix_unit_sha256':provision['unit_sha256'],'retirement_sha256':backup.sha(retired_raw),'scope':'replace only inactive SDK5 runtime fragment; retain exact backup'}
def plan():
 with backup.locked():return plan_locked()
def apply(approved):
 with backup.locked():
  require(plan_locked()==approved,'unit upgrade changed');old.store(START,backup.canonical(approved),0o600);old.store(BACKUP,guarded.units()[UNIT],0o644);old.store(TEMP,unit(),0o644);old.read(BACKUP,0o644,approved['prior_sha256']);old.read(TEMP,0o644,approved['unit_sha256']);inactive();old.read(PATH,0o644,approved['prior_sha256']);os.replace(TEMP,PATH);old.syncdir(PATH.parent);old.ctl('daemon-reload');old.read(PATH,0o644,approved['unit_sha256']);inactive();retired_raw,_=backup.retirement_state();require(backup.sha(retired_raw)==approved['retirement_sha256'],'retirement changed');bplan=gate._json(old.read(backup.START,0o600,maxsize=1000000));retired.terminal(backup.RESTATE,bplan['restate']);old.read(backup.FENCE,0o600,backup.sha(b'offline\n'));old.read(backup.DROP,0o644,backup.sha(backup.dropin()));backup.verify_loaded_fence(bplan['restate'])
  result={'schema':1,'transition_id':T,'prior_sha256':approved['prior_sha256'],'unit_sha256':approved['unit_sha256'],'backup_path':str(BACKUP),'guarded_binary_sha256':approved['guarded_binary_sha256'],'unix_unit_sha256':approved['unix_unit_sha256'],'started':False};old.store(DONE,backup.canonical(result),0o600);return result
