"""Provision a distinct Unix-admin Restate unit; never start it here.

Fixed production transition only. Old Restate remains stopped and fenced; no
existing unit, data or gate marker is removed or modified by this participant.
"""
import json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_retirement_coordinator as retired
import nuc_registry_offline_backup as backup
import nuc_registry_pinned_binary as pinned_binary
import nuc_registry_restore_verify as restore
T=retired.T;UNIT='software-factory-goose-private-restate-unix.service'
CONFIG=old.ETC/'registry-transition-restate-unix.toml';START=gate.ROOT/'history'/(T+'.unix-restate-provision-started.json');DONE=gate.ROOT/'history'/(T+'.unix-restate-provision-complete.json')
PROBE_SOURCE=None;PROBE_SHA='d90fb65e96f992e7e5adedb97ecd5c9307fc94b501ff4e7aa9481aa9f8329496';PROBE=old.PREFIX/'registry-transition-unix-restate-probe.py'
CONF=b'listen-mode = "tcp"\n[admin]\nlisten-mode = "unix"\n'
def require(v,m):
 if not v:raise RuntimeError(m)
def unit():
 anchor=retired.attestation.ANCHOR_UNIT
 return (f'[Unit]\nDescription=Factory fixed Unix-admin Restate\nBindsTo={anchor}\nAfter={anchor}\nJoinsNamespaceOf={anchor}\n[Service]\nType=exec\nUser=sfgoose-journal\nGroup=sfgoose-journal\nPrivateNetwork=yes\nProtectSystem=strict\nReadWritePaths={backup.SOURCE}\nProtectHome=yes\nPrivateTmp=yes\nUMask=0077\nEnvironment=TOKIO_WORKER_THREADS=2\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestart=no\nMemoryMax=2G\nTasksMax=128\nCPUQuota=100%\nExecStart={backup.BINARY} --config-file {CONFIG} --base-dir {backup.SOURCE} --node-name sfgoose-private --bind-ip 127.0.0.1 --use-random-ports false --no-logo\n').encode()
def plan_locked():
 require(os.geteuid()==0 and os.getegid()==0 and isinstance(PROBE_SOURCE,bytes) and backup.sha(PROBE_SOURCE)==PROBE_SHA and not any(os.path.lexists(p) for p in (START,DONE,CONFIG,PROBE,old.UNIT/UNIT)),'Unix Restate provision occupied')
 retirement_raw,_=backup.retirement_state();braw=old.read(backup.DONE,0o600);breceipt=gate._json(braw);bplan=gate._json(old.read(backup.START,0o600,maxsize=1000000))
 require(breceipt.get('schema')==1 and breceipt.get('transition_id')==T and breceipt.get('retirement_sha256')==backup.sha(retirement_raw) and breceipt.get('restate_stopped') is True and breceipt.get('restore_verified') is False and breceipt.get('plan_sha256')==backup.sha(backup.canonical(bplan)),'offline backup unavailable')
 rraw=old.read(restore.DONE,0o600);r=gate._json(rraw);require(r.get('schema')==1 and r.get('transition_id')==T and r.get('scoped_state_match') is True and r.get('owned_units_terminal') is True and r.get('full_journal_verified') is False and r.get('promotion_authorized') is False and r.get('baseline_sha256')==bplan['history_baseline_sha256'],'restore comparison unavailable')
 retired.terminal(backup.RESTATE,bplan['restate']);old.read(backup.FENCE,0o600,backup.sha(b'offline\n'));old.read(backup.DROP,0o644,backup.sha(backup.dropin()));backup.verify_loaded_fence(bplan['restate']);pinned_binary.verify(backup.BINARY,backup.BINARY_SHA);old.directory(backup.SOURCE.parent,2004,2004,0o700);old.directory(backup.SOURCE,2004,2004,0o755);old.directory(backup.SOURCE/'sfgoose-private',2004,2004,0o755)
 st=backup.SOURCE.stat();require((st.st_dev,st.st_ino)==(bplan['source_dev'],bplan['source_ino']),'data identity changed')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied');paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit search unavailable');stem=UNIT.removesuffix('.service')
 for parent in map(pathlib.Path,paths):
  for n in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(parent/n),'unit collision')
 return {'schema':1,'transition_id':T,'backup_sha256':backup.sha(braw),'restore_sha256':backup.sha(rraw),'data_dev':st.st_dev,'data_ino':st.st_ino,'unit_sha256':backup.sha(unit()),'config_sha256':backup.sha(CONF),'probe_sha256':PROBE_SHA,'scope':'create-only Unix-admin Restate unit; no start or data change'}
def plan():
 with backup.locked():return plan_locked()
def breceipt_retirement(approved):
 raw=old.read(backup.DONE,0o600,approved['backup_sha256']);return gate._json(raw)['retirement_sha256']
def apply(approved):
 with backup.locked():
  require(plan_locked()==approved,'provision plan changed');old.store(START,backup.canonical(approved),0o600);old.store(CONFIG,CONF,0o644);old.store(PROBE,PROBE_SOURCE,0o755);old.store(old.UNIT/UNIT,unit(),0o644);old.ctl('daemon-reload')
  old.read(CONFIG,0o644,approved['config_sha256']);old.read(PROBE,0o755,PROBE_SHA);old.read(old.UNIT/UNIT,0o644,approved['unit_sha256']);p=retired.properties(UNIT);require(p.get('LoadState')=='loaded' and p.get('Names')==UNIT and p.get('FragmentPath')==str(old.UNIT/UNIT) and p.get('DropInPaths','')=='' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='','unit not inactive')
  retired_raw,_=backup.retirement_state();require(backup.sha(retired_raw)==breceipt_retirement(approved),'retirement changed');bplan=gate._json(old.read(backup.START,0o600,maxsize=1000000));retired.terminal(backup.RESTATE,bplan['restate']);old.read(backup.FENCE,0o600,backup.sha(b'offline\n'));old.read(backup.DROP,0o644,backup.sha(backup.dropin()));backup.verify_loaded_fence(bplan['restate'])
  result={'schema':1,'transition_id':T,'started':False,'data_changed':False,'backup_sha256':approved['backup_sha256'],'restore_sha256':approved['restore_sha256'],'unit_sha256':approved['unit_sha256'],'config_sha256':approved['config_sha256'],'probe_sha256':PROBE_SHA};old.store(DONE,backup.canonical(result),0o600);return result
