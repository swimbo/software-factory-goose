"""Publish the reviewed additive SDK5 catalog while the transition is closed."""
import os
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_retirement_coordinator as retired
import nuc_registry_offline_backup as backup
import nuc_registry_v5_manifest_candidate as candidate
import nuc_registry_v5_install as v5
import nuc_registry_sidecar_install as prior
import nuc_registry_unix_restate_activate as unix
T=retired.T;ROOT=old.ETC;CONFIG=ROOT/candidate.CONFIG;EVIDENCE=ROOT/candidate.EVIDENCE;REG=gate.REGISTRY
BACKUP=ROOT/('catalog-registry.pre-v5-'+T.lower()+'.json');TEMP=ROOT/('catalog-registry.v5-new-'+T.lower()+'.json');START=gate.ROOT/'history'/(T+'.catalog-publish-started.json');DONE=gate.ROOT/'history'/(T+'.catalog-publish-complete.json')
def require(v,m):
 if not v:raise RuntimeError(m)
def inputs():
 prior_raw=gate._protected_read(REG,0o644,65536);cfg,config,_=v5.proposed_config();evidence=old.read(prior.EVIDENCE,0o644);proposal=candidate.build(prior_raw,config,evidence)
 return prior_raw,config,evidence,proposal
def plan_locked():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (CONFIG,EVIDENCE,BACKUP,TEMP,START,DONE)),'catalog publication occupied')
 retired_raw,_=backup.retirement_state();activation=gate._json(old.read(unix.DONE,0o600));require(activation.get('transition_id')==T and activation.get('gate_closed') is True and activation.get('journal_admin_ok') is True and activation.get('control_admin_denied') is True and activation.get('tcp_admin_absent') is True,'Unix admin unavailable')
 state=retired.observe(unix.provision.UNIT);require(state==activation['identity'],'Unix Restate changed')
 prior_raw,config,evidence,proposal=inputs();marker=gate._json(gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000));require(marker=={'schema':1,'transition_id':T,'old_manifest_sha256':proposal['old_manifest_sha256'],'new_manifest_sha256':proposal['new_manifest_sha256']},'transition intent changed')
 return {'schema':1,'transition_id':T,'retirement_sha256':backup.sha(retired_raw),'unix_activation_sha256':backup.sha(old.read(unix.DONE,0o600)),'prior_sha256':backup.sha(prior_raw),'config_sha256':backup.sha(config),'evidence_sha256':backup.sha(evidence),'manifest_sha256':proposal['new_manifest_sha256'],'scope':'atomic additive fixed SDK5 catalog publication; gate remains closed'}
def plan():
 with backup.locked():return plan_locked()
def apply(approved):
 with backup.locked():
  require(plan_locked()==approved,'catalog plan changed');old.store(START,backup.canonical(approved),0o600);prior_raw,config,evidence,proposal=inputs()
  old.store(BACKUP,prior_raw,0o644);old.store(CONFIG,config,0o644);old.store(EVIDENCE,evidence,0o644);old.store(TEMP,candidate.canonical(proposal['manifest']),0o644)
  old.read(BACKUP,0o644,approved['prior_sha256']);old.read(CONFIG,0o644,approved['config_sha256']);old.read(EVIDENCE,0o644,approved['evidence_sha256']);old.read(TEMP,0o644,approved['manifest_sha256']);require(backup.sha(gate._protected_read(REG,0o644,65536))==approved['prior_sha256'],'registry changed');require(retired.observe(unix.provision.UNIT)==gate._json(old.read(unix.DONE,0o600))['identity'],'Unix Restate changed')
  os.replace(TEMP,REG);old.syncdir(REG.parent);require(backup.sha(gate._protected_read(REG,0o644,65536))==approved['manifest_sha256'],'registry publication unknown');retired_raw,_=backup.retirement_state();require(backup.sha(retired_raw)==approved['retirement_sha256'],'retirement changed')
  result={'schema':1,'transition_id':T,'prior_sha256':approved['prior_sha256'],'manifest_sha256':approved['manifest_sha256'],'config_sha256':approved['config_sha256'],'evidence_sha256':approved['evidence_sha256'],'backup_path':str(BACKUP),'gate_closed':True};old.store(DONE,backup.canonical(result),0o600);return result
