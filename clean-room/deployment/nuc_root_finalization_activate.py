"""Fixed finalization activation candidate; unavailable until SDK5 admission is proved.

Admission requires the shared native SDK5 receipt and live provenance adapter.
Its producer must be reviewed and installed before this can start.
No publication or journal invocation is performed here.
"""
import json,os
import nuc_evidence_reader_canary as guard
import nuc_root_authorization_canary as auth
import nuc_registry_transition_gate as gate
import nuc_root_finalization_activation_plan as preflight
import nuc_root_finalization_attest as attest
import nuc_registry_v5_admission as admission
sdk5=admission

INTENT=attest.ROOT/(attest.G+'.activation-intent.json')
DONE=attest.ROOT/(attest.G+'.activation-complete.json')

def require_sdk5_admission():
    guard.require(sdk5.PRODUCER_SHA256 is not None, 'SDK5 ingress admission and old-SDK retirement proof unavailable')
    return admission.verify()

def plan_locked():
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required')
    sdk5_state=require_sdk5_admission()
    guard.require(not os.path.lexists(INTENT) and not os.path.lexists(DONE),'activation intent occupied')
    state=preflight.plan()
    return {'schema':1,'purpose':'fixed-root-finalization-activation-only','generation':attest.G,'preflight':state,'sdk5_admission':sdk5_state,'journal_invocation':False,'authorization_publication':False}

def plan():
    with gate.admission():return plan_locked()

def apply(reviewed):
    with gate.admission():
        guard.require(plan_locked()==reviewed,'activation plan changed')
        auth.create(INTENT,(json.dumps(reviewed,sort_keys=True)+'\n').encode(),0o600)
        attest.old.ctl('daemon-reload')
        attest.old.ctl('start',attest.SOCKET_UNIT)
        attest.old.ctl('start',attest.SERVICE)
        post=attest.plan()
        result=attest.apply(post)
        result.update(status='active-attested',authorization_published=False,journal_invoked=False)
        auth.create(DONE,(json.dumps(result,sort_keys=True)+'\n').encode(),0o600)
        return result
