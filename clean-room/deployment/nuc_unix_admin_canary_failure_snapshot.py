"""Fixed read-only synthetic journal snapshot after failed probe."""
import os
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_probe_start as probe
import nuc_unix_admin_canary_snapshot_supervisor as snapshot
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and os.path.lexists(probe.START) and not os.path.lexists(probe.DONE),'failed probe evidence unavailable')
 require(old.ctl('show',probe.UNIT,'-p','ActiveState','--value')=='failed' and old.ctl('show',probe.UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',probe.UNIT,'-p','Job','--value')=='','probe not terminal')
 snapshot.ACTIONS['failure']='snapshot';snapshot.ROLE='failure';return snapshot.plan()
def apply(approved):
 require(plan()==approved,'snapshot plan changed');snapshot.ACTIONS['failure']='snapshot';snapshot.ROLE='failure';return snapshot.apply(approved)
