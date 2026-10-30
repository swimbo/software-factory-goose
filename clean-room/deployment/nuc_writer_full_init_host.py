"""Fixed source-pinned wrapper for synthetic writer initialization canary."""
import hashlib,json
import nuc_grant_sidecar_install as old
import nuc_registry_launch_prepare as prep
import nuc_writer_full_init_canary as fixture
HELPER_SHA='604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e'
PACKAGE_SHA='4cb5a74f7a8027c03edb217b3a5e83ac0af968749cbba6124480c760db8380af'
def load():
 old.read(old.ETC/'relay-package.json',0o600,PACKAGE_SHA);raw=old.read(old.PREFIX/'root-launch-host.py',0o755,HELPER_SHA,1_000_000)
 h={'__name__':'writer_canary_fixed_helper'};exec(compile(raw,'<pinned-root-launch-helper>','exec'),h);deadline,_=h['modules']()
 provider=prep.provider();images=prep.root_json(old.ETC/'worker-images.json')
 if images.get('schema')!=1 or images.get('engine_started') is not False or images.get('writer',{}).get('image_id')!=h['WRITER'] or images['writer'].get('program_sha256')!=h['WRITER_SHA']:raise RuntimeError('fixed images unavailable')
 prior=old.old_snapshot();sidecar=old.sidecar_running();real=prep.real.service_running();registry=prep.registry.service_running()
 return h,deadline,provider,images,{'old':prior,'prior_sidecar':sidecar,'real_sidecar':real,'registry_sidecar':registry}
def plan():
 h,deadline,provider,images,history=load();result=fixture.plan_host(old,h,deadline,provider,images);result['history']=history;result['package_sha256']=PACKAGE_SHA;result['helper_sha256']=HELPER_SHA;return result
def apply(approved):
 if plan()!=approved:raise RuntimeError('canary plan changed')
 h,deadline,provider,images,history=load();scope={k:v for k,v in approved.items() if k not in ('history','package_sha256','helper_sha256')}
 result=fixture.apply_host(scope,old,h,deadline,prep,provider,images)
 if load()[-1]!=history:raise RuntimeError('preserved service changed')
 return result
