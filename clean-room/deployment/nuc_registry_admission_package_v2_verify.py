"""Read-only fixed installed admission v2 package and import closure check."""
import ast,hashlib,json,os
import nuc_grant_sidecar_install as old
import nuc_registry_admission_package_v2_install as package
DONE=old.ETC/'registry-v5-admission-package-v2-verify.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'verification occupied')
 receipt_raw=old.read(package.DONE,0o600);receipt=json.loads(receipt_raw);expected=hashlib.sha256(package.LAUNCHER).hexdigest();require(receipt=={'schema':1,'installed':True,'executed':False,'activated':False,'launcher_sha256':expected},'installation receipt mismatch')
 old.directory(package.ROOT,0,0,0o755);require(set(os.listdir(package.ROOT))==set(package.PINS),'package entries mismatch');imports=set()
 for name,digest in package.PINS.items():
  raw=old.read(package.ROOT/name,0o644,digest,1000000);tree=ast.parse(raw)
  imports|={a.name for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names if a.name.startswith('nuc_')}
  imports|={n.module for n in ast.walk(tree) if isinstance(n,ast.ImportFrom) and n.module and n.module.startswith('nuc_')}
 require(all(name+'.py' in package.PINS for name in imports),'static import closure unavailable')
 old.read(package.TARGET,0o755,expected,1000000)
 return {'schema':1,'installation_sha256':hashlib.sha256(receipt_raw).hexdigest(),'launcher_sha256':expected,'files':len(package.PINS),'static_import_closure':True,'scope':'read-only protected package identity; no producer execution'}
def apply(approved):
 require(plan()==approved,'verification changed');old.store(DONE,package.canonical(approved),0o600);return approved
