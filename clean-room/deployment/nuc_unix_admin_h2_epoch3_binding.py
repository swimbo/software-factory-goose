"""Bind retained pre-retirement evidence to a separately started data epoch."""
import json,os,pathlib
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_sdk_start as sdk
START=old.ETC/'unix-admin-h2-canary-epoch3-binding-started.json';DONE=old.ETC/'unix-admin-h2-canary-epoch3-binding-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE),'binding occupied')
 epochraw=old.read(old.ETC/'unix-admin-h2-canary-epoch3-complete.json',0o600);epoch=json.loads(epochraw);sdk.verify_epoch(epoch)
 invraw=old.read(old.ETC/'unix-admin-h2-canary-epoch3-inventory.json',0o600);inv=json.loads(invraw);old.directory(base.DATA,2004,2004,0o700);s=base.DATA.stat();require((s.st_dev,s.st_ino)==(inv.get('data_dev'),inv.get('data_ino'))==(66306,19142983),'data identity changed')
 paths=('unix-admin-h2-canary-epoch2-complete.json','unix-admin-h2-canary-snapshot-baseline-complete.json','unix-admin-h2-canary-before-retirement.json','unix-admin-h2-canary-history-output-baseline.json','unix-admin-h2-canary-after-journal.json','unix-admin-h2-canary-register-new-unknown.json');digests={}
 for name in paths:digests[name]=base.sha(old.read(old.ETC/name,0o600,maxsize=196608))
 require(digests[paths[0]]==inv['prior_epoch_sha256'] and digests[paths[4]]==inv['postretire_sha256'] and digests[paths[5]]==inv['unknown_sha256'],'retained evidence changed')
 return {'schema':1,'epoch3_sha256':base.sha(epochraw),'inventory_sha256':base.sha(invraw),'data_dev':s.st_dev,'data_ino':s.st_ino,'prior':digests,'9082_outcome':'unknown','scope':'bind retained evidence to same data inode; no registration'}
def apply(approved):
 require(plan()==approved,'binding changed');old.store(START,base.canonical(approved)+b'\n',0o600);old.store(DONE,base.canonical(approved)+b'\n',0o600);return approved
