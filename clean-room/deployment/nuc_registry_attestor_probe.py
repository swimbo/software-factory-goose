"""Run the installed read-only registry process attestor; never request a grant."""
import json,os,subprocess
import nuc_grant_sidecar_install as old
PROBE=old.PREFIX/'registry-attestor-probe'; SHA='aa2868160da22acbdae103c118f952cc8d8675fe31b0558dec969c7f96b21642'
ATTEST=old.ETC/'registry-process-attestation.json'; ATTEST_SHA='e7ae655d6aee361836518cf6f750053cb54c535e37b57326d218706915453a7a'
START=old.ETC/'registry-attestor-probe-started.json';DONE=old.ETC/'registry-attestor-probe-complete.json'
def plan():
 if os.geteuid()!=0 or any(os.path.lexists(p) for p in (START,DONE)):raise RuntimeError('probe already attempted or root unavailable')
 old.read(PROBE,0o755,SHA,10000000);old.read(ATTEST,0o600,ATTEST_SHA)
 return {'probe_sha256':SHA,'attestation_sha256':ATTEST_SHA,'scope':'read-only process attestation; no grant'}
def apply(approved):
 if plan()!=approved:raise RuntimeError('probe plan changed')
 old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 p=subprocess.run([str(PROBE)],env=old.ENV,capture_output=True,timeout=50,check=False)
 if p.returncode!=0 or len(p.stdout)>8192 or len(p.stderr)>8192:raise RuntimeError('probe failed or outcome unknown')
 value=json.loads(p.stdout)
 if value!={'service_attested':True,'grant_requested':False}:raise RuntimeError('unexpected attestor output')
 old.read(ATTEST,0o600,ATTEST_SHA);result={**approved,**value};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
