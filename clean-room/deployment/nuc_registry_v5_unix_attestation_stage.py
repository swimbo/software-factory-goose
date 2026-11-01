"""Fixed transition attestation; marker and exclusive lock are never caller-selected."""
import os
import nuc_registry_offline_backup as backup
import nuc_registry_retirement_coordinator as retired
import nuc_registry_transition_gate as gate
import nuc_registry_v5_unix_attestation as attest

def intent():
 raw=gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000);value=gate._json(raw)
 gate.require(value.get('transition_id')==retired.T,'transition unavailable');return value

def plan():
 with backup.locked():
  backup.retirement_state();value=intent();return {'schema':1,'transition_id':retired.T,'intent_sha256':backup.sha(gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000)),'binding':attest.plan(value)}

def apply(reviewed):
 with backup.locked():
  backup.retirement_state();value=intent();current={'schema':1,'transition_id':retired.T,'intent_sha256':backup.sha(gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000)),'binding':attest.plan(value)}
  gate.require(current==reviewed,'attestation stage changed');result=attest.apply(value,current['binding']);backup.retirement_state();gate.require(intent()==value,'transition changed');return result
