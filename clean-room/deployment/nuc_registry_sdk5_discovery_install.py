"""Create-only pinned non-dumpable SDK5 discovery probe; no execution."""
import os,pathlib
import nuc_grant_sidecar_install as old
import nuc_registry_offline_backup as backup
SOURCE=pathlib.Path('/tmp/sfactory-sdk5-fdguard-20261030/sdk5-discovery-v3');SOURCE_SHA='0ef90fd7f7ac2dc73fb228bd87d0f0878c7155252173419a850f5c624fbed360';TARGET=old.PREFIX/'registry-v5-discovery-probe';START=old.ETC/'registry-v5-discovery-probe-install-started.json';DONE=old.ETC/'registry-v5-discovery-probe-install-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def binary(dest=None):
 previous=(old.SOURCE,old.SOURCE_SHA)
 try:old.SOURCE=SOURCE;old.SOURCE_SHA=SOURCE_SHA;return old.binary(dest)
 finally:old.SOURCE,old.SOURCE_SHA=previous
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (TARGET,START,DONE)),'probe occupied');old.directory(old.PREFIX,0,0,0o755);old.directory(SOURCE.parent,1000,1000,0o700)
 return {'schema':1,'binary':binary(),'scope':'create-only SDK5 discovery probe; no execution'}
def apply(approved):
 require(plan()==approved,'probe plan changed');old.store(START,backup.canonical(approved),0o600);require(binary(TARGET)==approved['binary'],'probe changed');old.syncdir(TARGET.parent);old.read(TARGET,0o755,SOURCE_SHA,10000000)
 result={'schema':1,'sha256':SOURCE_SHA,'installed':True,'executed':False};old.store(DONE,backup.canonical(result),0o600);return result
