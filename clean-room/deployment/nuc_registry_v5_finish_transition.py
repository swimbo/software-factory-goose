"""Fixed SDK5 gate finisher; the admission marker remains until all proofs pass."""
import os
import nuc_grant_sidecar_install as old
import nuc_registry_offline_backup as backup
import nuc_registry_retirement_coordinator as retired
import nuc_registry_transition_gate as gate
import nuc_registry_v5_replay_finish as replay
T=retired.T

def plan_locked():
 retired_raw,_=backup.retirement_state()
 marker=gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000);intent=gate._json(marker)
 gate.require(intent.get('transition_id')==T,'transition unavailable')
 raw=old.read(replay.DONE,0o600, maxsize=16384);proof=gate._json(raw)
 gate.require(proof.get('transition_id')==T and proof.get('producer_sha256')==replay.HANDLER_SHA and proof.get('old_manifest_sha256')==intent.get('old_manifest_sha256') and proof.get('new_manifest_sha256')==intent.get('new_manifest_sha256'),'replay unavailable')
 old.read(replay.HANDLER,0o755,replay.HANDLER_SHA,1000000)
 return {'schema':1,'transition_id':T,'intent_sha256':backup.sha(marker),'replay_sha256':backup.sha(raw),'retirement_sha256':backup.sha(retired_raw),'scope':'verify prospective admission and finish the fixed registry transition'}
def plan():
 with backup.locked():return plan_locked()
def apply(reviewed):
 with backup.locked():
  gate.require(plan_locked()==reviewed,'finish plan changed')
  marker=gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000);intent=gate._json(marker)
  gate.REPLAY_PRODUCER=replay.HANDLER;gate.REPLAY_PRODUCER_SHA=replay.HANDLER_SHA
  directory=gate._directory(gate.ROOT,0,2000,0o710)
  try:head=gate.finish_transition(directory,intent)
  finally:os.close(directory)
  return {'schema':1,'transition_id':T,'head':head,'admission_verified':True,'promotion':False}
