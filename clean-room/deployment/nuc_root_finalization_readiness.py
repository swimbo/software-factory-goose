"""Native root cap-empty fixed evidence check; no publication or network effect."""
import hashlib,json,os,pathlib,re,subprocess
import nuc_evidence_reader_canary as guard
import nuc_root_authorization_canary as auth
import nuc_root_finalization_prepare as prep
import nuc_root_finalization_readiness_install as install

UNIT='sfactory-root-finalization-readiness.service'
INTENT=prep.old.ETC/(prep.G+'.finalization-readiness-intent.json')
DONE=prep.old.ETC/(prep.G+'.finalization-readiness-result.json')

def plan():
    guard.require(os.geteuid()==0 and os.getegid()==0,'root required')
    guard.require(not os.path.lexists(INTENT) and not os.path.lexists(DONE),'readiness intent occupied')
    auth.pin(install.TARGET,install.SHA)
    prep.old.directory(prep.STOP,0,0,0o700);prep.old.directory(prep.DEST,0,0,0o755)
    request,config=prep.inputs()
    guard.require(prep.old.read(prep.REQUEST,0o600)==request and prep.old.read(prep.CONFIG,0o600)==config,'prepared evidence changed')
    value=prep.strict(config);guard.require(value['boot_id']==pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'boot changed')
    for tool in (pathlib.Path('/usr/bin/systemctl'),pathlib.Path('/usr/bin/systemd-run'),pathlib.Path('/usr/bin/systemd-analyze')):guard.fixed_tool(tool)
    paths=auth.subprocess.run(['/usr/bin/systemd-analyze','--system','unit-paths'],env=auth.ENV,capture_output=True,timeout=5,check=True).stdout.decode().splitlines()
    guard.require(paths and len(paths)<=64 and all(pathlib.Path(p).is_absolute() for p in paths),'unit paths unavailable')
    name=UNIT.removesuffix('.service')
    for parent in paths:
        for candidate in [UNIT,UNIT+'.d','service.d']+[name[:i+1]+'.service.d' for i,c in enumerate(name) if c=='-']:
            guard.require(not os.path.lexists(pathlib.Path(parent)/candidate),'unit path or drop-in occupied')
    state=subprocess.run(['/usr/bin/systemctl','show',UNIT,'-p','LoadState','--value'],env=auth.ENV,capture_output=True,timeout=5,check=True).stdout.strip()
    guard.require(state in (b'',b'not-found'),'readiness unit occupied')
    return {'schema':1,'purpose':'native-root-unknown-evidence-readiness-only','generation':prep.G,'boot_id':value['boot_id'],'binary_sha256':install.SHA,'request_file_sha256':hashlib.sha256(request).hexdigest(),'config_sha256':hashlib.sha256(config).hexdigest(),'unit':UNIT,'journal_or_publication':False}

def apply(reviewed):
    guard.require(plan()==reviewed,'readiness plan changed')
    auth.create(INTENT,(json.dumps(reviewed,sort_keys=True)+'\n').encode(),0o600)
    result=auth.run_unit(UNIT.removesuffix('.service'),0,install.TARGET,[prep.G])
    guard.require(result.returncode==0 and re.fullmatch(rb'PASS: fixed unknown evidence verified; request_sha256=[0-9a-f]{64}\n',result.stdout) is not None,'readiness unresolved; retain intent')
    outcome={'schema':1,'status':'passed','generation':prep.G,'record_sha256':result.stdout.decode().strip().split('=')[1],'authorization_published':False}
    auth.create(DONE,(json.dumps(outcome,sort_keys=True)+'\n').encode(),0o600)
    return outcome
