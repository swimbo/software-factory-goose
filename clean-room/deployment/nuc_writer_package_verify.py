"""Native cap-zero verification of writer package v2; no service start."""
import json
import nuc_callback_upgrade_verify as v
import nuc_grant_sidecar_install as old
NEW='0e9f0bf575a26218b150d0bc67adb1124caf18e4fe7496411c802d67f0f7e842'
v.pkg.PINS=dict(v.pkg.PINS);v.pkg.PINS['nuc_root_writer_service.py']=NEW
v.UNIT='sfactory-writer-upgrade-verify.service';v.START=old.ETC/'writer-upgrade-verify-started.json';v.DONE=old.ETC/'writer-upgrade-verify-complete.json'

def plan():
 receipt=json.loads(old.read(old.ETC/'writer-upgrade-complete.json',0o600))
 if receipt.get('writer_sha256')!=NEW or receipt.get('grant_requested') is not False or receipt.get('engine_effects') is not False:raise RuntimeError('writer upgrade receipt unavailable')
 return v.plan()
def apply(approved):
 if plan()!=approved:raise RuntimeError('verification plan changed')
 return v.apply(approved)
