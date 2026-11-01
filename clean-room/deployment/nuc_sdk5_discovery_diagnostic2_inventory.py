"""Read only fixed synthetic probe capture; no retry or service control."""
import os
import nuc_grant_sidecar_install as old
import nuc_sdk5_discovery_native_diagnostic2 as fixture

def plan():
 if os.geteuid()!=0 or os.path.lexists(fixture.DONE):raise RuntimeError('unexpected diagnostic state')
 intent=old.read(fixture.START,0o600);stdout=old.read(fixture.ROOT/'positive-stdout',0o600,maxsize=8192);stderr=old.read(fixture.ROOT/'positive-stderr',0o600,maxsize=8192)
 return {'schema':1,'intent_sha256':fixture.backup.sha(intent),'stdout_bytes':len(stdout),'stderr_bytes':len(stderr),'synthetic_stderr':stderr.decode('utf-8','replace'),'negative_attempted':os.path.lexists(fixture.ROOT/'negative-stderr'),'scope':'bounded synthetic error only; no retry'}
def apply(_):raise RuntimeError('read-only inventory only')
