"""Fixed protected evaluator catalog validation; no deployment or listener start."""
import hashlib,json,os,pathlib,re,stat
import nuc_registry_eval_backend_v3 as backend
import nuc_grant_sidecar_install as old
CAT=old.ETC/'evaluator-catalog.json';STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
COORD=pathlib.Path('/usr/local/libexec/software-factory-goose/evaluator-production-v2');SOURCE=COORD/'nuc_registry_evaluator.py'
def unique(pairs):
 out={}
 for k,v in pairs:
  if k in out:raise backend.Unavailable('duplicate catalog field')
  out[k]=v
 return out
def catalog(source_sha, *, _path=CAT, _expected_generation=None):
 if os.geteuid()!=0 or not isinstance(source_sha,str) or not re.fullmatch(r'[0-9a-f]{64}',source_sha):raise backend.Unavailable('bootstrap unavailable')
 # The coordinator is readable by the dedicated evaluation group only.
 fd=os.open(COORD,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);old.noacl(fd,True)
  if (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(0,2002,0o750):raise backend.Unavailable('coordinator directory unavailable')
  child=os.open(SOURCE.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
  try:
   st=os.fstat(child);old.noacl(child)
   if not stat.S_ISREG(st.st_mode) or (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))!=(0,2002,1,0o440) or st.st_size>65536:raise backend.Unavailable('coordinator unavailable')
   raw=os.read(child,65537)
   if len(raw)!=st.st_size or hashlib.sha256(raw).hexdigest()!=source_sha:raise backend.Unavailable('coordinator changed')
  finally:os.close(child)
 finally:os.close(fd)
 obj=json.loads(old.read(_path,0o600,maxsize=65536),object_pairs_hook=unique)
 if not isinstance(obj,dict) or set(obj)!={'schema','generation','snapshot_sha256','challenges','boot_id','reconcile_sha256'} or type(obj['schema']) is not int or obj['schema']!=1 or not isinstance(obj['generation'],str) or backend.ID.fullmatch(obj['generation']) is None:raise backend.Unavailable('catalog unavailable')
 gen=obj['generation']
 if _expected_generation is not None and gen!=_expected_generation:raise backend.Unavailable('generation changed')
 receipt_raw=old.read(STATE/(gen+'.reconcile-complete.json'),0o600,obj['reconcile_sha256']);receipt=json.loads(receipt_raw,object_pairs_hook=unique)
 if receipt.get('generation')!=gen or receipt.get('candidate_sha256')!=obj['snapshot_sha256'] or any(receipt.get(k) is not True for k in ('kernel_closed_frozen_empty','exact_ids_removed','slice_retained_frozen','engine_reconciled_for_exact_ids')):raise backend.Unavailable('reconciliation unavailable')
 current=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 if obj['boot_id']!=current or not isinstance(obj['challenges'],list) or len(obj['challenges'])!=22:raise backend.Unavailable('catalog unavailable')
 allowed={'target','task_id','cgroup_dev','cgroup_ino','snapshot_path','snapshot_dev','snapshot_ino','generation'};targets=set()
 for e in obj['challenges']:
  if not isinstance(e,dict) or set(e)!=allowed or e['generation']!=gen or not isinstance(e['target'],str) or backend.ID.fullmatch(e['target']) is None or e['target'] in targets or backend.verify_snapshot(e,old.noacl)!=obj['snapshot_sha256']:raise backend.Unavailable('challenge unavailable')
  targets.add(e['target'])
 return {k:v for k,v in obj.items() if k!='reconcile_sha256'}


def active_catalog(source_sha):
 # The protected registry, not a socket peer or command argument, chooses the
 # sole active generation. No fixture catalog is eligible at this path.
 import nuc_registry_eval_snapshot_provision as provision
 import nuc_registry_transition_gate as gate
 with gate.admission():
  generation,_,_=provision.selected()
  return catalog(source_sha,_path=old.ETC/(generation+'.evaluator-catalog.json'),_expected_generation=generation)
