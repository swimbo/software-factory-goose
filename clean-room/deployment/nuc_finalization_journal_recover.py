"""Fixed, single-invocation completion recovery after interrupted SDK startup.

Never starts or restarts the SDK. Root/PID1 and UID1000 are trusted; retains
intent/records on any ambiguous outcome. Synthetic fixture only.
"""
import json,os,pathlib
import nuc_evidence_reader_canary as guard
import nuc_root_authorization_canary as auth
import nuc_finalization_journal_fixture as fixture

BOOT='98b86bb5-c04c-46f5-951d-22e497102f29'
PID='1162116'
INVOCATION='1dda810d81a3403abc7bd36f1852e7b0'
RECOVERY_INTENT=fixture.BASE.parent/'journal-fixture.start-recovery-intent.json'

def plan():
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required')
    guard.require(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT,'boot changed')
    original=fixture.recorded_plan_from_root()
    guard.require(not any(os.path.lexists(p) for p in (RECOVERY_INTENT,fixture.UNIT_RECORD,fixture.START_DONE)),'recovery path occupied')
    auth.pin(fixture.SDK,fixture.SDK_SHA);auth.pin(fixture.ATTESTOR,fixture.ATTESTOR_SHA)
    info=fixture.unit_info()
    expected='{ path='+str(fixture.SDK)+' ; argv[]='+str(fixture.SDK)+' 127.0.0.1:48291 ; '
    guard.require(info.get('LoadState')=='loaded' and info.get('ActiveState')=='active' and info.get('MainPID')==PID and info.get('InvocationID')==INVOCATION and info.get('User')=='2000' and info.get('Group')=='2000' and info.get('NoNewPrivileges')=='yes' and info.get('ExecStart','').startswith(expected) and info['ExecStart'].count('{')==1 and info['ExecStart'].count('}')==1,'owned unit mismatch')
    fixture.verify_process(info)
    unit='sfactory-finalization-pg-recover.service'
    state=fixture.run(['/usr/bin/systemctl','show',unit,'-p','LoadState','--value']).stdout.strip()
    guard.require(state in (b'',b'not-found'),'recovery attestor occupied')
    paths=fixture.run(['/usr/bin/systemd-analyze','--system','unit-paths']).stdout.decode().splitlines()
    guard.require(paths and len(paths)<=64 and all(pathlib.Path(p).is_absolute() for p in paths),'unit paths unavailable')
    name=unit.removesuffix('.service')
    for parent in paths:
        for candidate in [unit,unit+'.d','service.d']+[name[:i+1]+'.service.d' for i,c in enumerate(name) if c=='-']:
            guard.require(not os.path.lexists(pathlib.Path(parent)/candidate),'recovery unit or drop-in occupied')
    return {'schema':1,'purpose':'complete-existing-synthetic-sdk-start-only','fixture_sha256':fixture.digest(original),'boot_id':BOOT,'pid':PID,'invocation_id':INVOCATION,'unit':fixture.UNIT,'unit_info':info,'starts_sdk':False}

def apply(reviewed):
    guard.require(plan()==reviewed,'recovery plan changed')
    auth.create(RECOVERY_INTENT,(json.dumps(reviewed,sort_keys=True)+'\n').encode(),0o600)
    auth.create(fixture.UNIT_RECORD,(json.dumps(reviewed['unit_info'],sort_keys=True)+'\n').encode(),0o600)
    fixture.attest_pg('sfactory-finalization-pg-recover')
    fixture.owned_unit()
    auth.create(fixture.START_DONE,b'{"schema":1,"started":true}\n',0o444)
    return {'status':'existing-start-completed','pid':PID,'invocation_id':INVOCATION,'records_retained':True}
