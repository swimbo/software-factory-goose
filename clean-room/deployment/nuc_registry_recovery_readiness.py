"""Read-only pre-retirement backup/restore prerequisite inventory."""
import json,os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_offline_backup as backup
import nuc_registry_restore_prepare as restore
import nuc_registry_restore_verify as verify
import nuc_registry_restore_history as history
import nuc_registry_pinned_binary as pinned
import nuc_registry_retirement_coordinator as retirement
import nuc_restate_source_inventory as inventory
import nuc_registry_retirement_coordinator as retired
DONE=old.ETC/'registry-recovery-readiness.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan_locked():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'readiness occupied')
 head=gate.verify_head();binary=pinned.verify(backup.BINARY,backup.BINARY_SHA)
 capraw=old.read(backup.cap_canary.DONE,0o600);cap=gate._json(capraw);require(cap.get('public_copy_equal') is True and cap.get('restore_equal') is True and cap.get('no_fowner') is True and cap.get('production_data') is False,'copy canary unavailable')
 restate=retired.observe(backup.RESTATE);backup.validate_active_restate(restate);sizing=inventory.inspect(backup.SOURCE,backup.DEST.parent)
 old.read(history.PROBE,0o755,history.PROBE_SHA,65536)
 destinations=(backup.START,backup.DONE,backup.TRANSPORT,backup.FENCE,backup.DROP,backup.DEST,restore.ROOT,restore.CONF,restore.START,restore.DONE,restore.TRANSPORT,verify.START,verify.DONE,verify.TRANSPORT,history.START,history.DONE,history.TRANSPORT)
 require(not any(os.path.lexists(x) for x in destinations),'recovery destination occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 units=(restore.NET,restore.SERVER,verify.NSUNIT,verify.PROBEUNIT,history.UNIT)
 for name in units:
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','recovery unit occupied');stem=name.removesuffix('.service')
  for root in map(pathlib.Path,paths):
   for n in [name,name+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/n),'unit collision')
 return {'schema':1,'gate_head_sha256':gate._digest(backup.canonical(head)),'restate':restate,'source_sizing':sizing,'binary':binary,'destinations_absent':True,'recovery_units_available':True,'history_probe_v2_sha256':history.PROBE_SHA,'scope':'read-only pre-retirement prerequisites; no backup, stop or restore proof'}
def plan():
 with gate.admission():return plan_locked()
def apply(approved):
 with gate.admission():
  require(plan_locked()==approved,'readiness changed');old.store(DONE,backup.canonical(approved),0o600);return approved
