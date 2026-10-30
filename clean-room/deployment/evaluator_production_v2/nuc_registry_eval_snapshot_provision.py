"""Create-only evaluator snapshot from the active registry's root reconciliation.

No fixture history, client-selected generation, evaluation or provider call is
accepted. The caller must install the composed root-reviewed helper first.
"""
import errno,hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
import nuc_registry_eval_provenance as provenance
import nuc_registry_transition_gate as gate
ROOT=old.ETC;STATE=pathlib.Path('/var/lib/software-factory-goose');REG=ROOT/'catalog-registry.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def unique(pairs):
 out={}
 for k,v in pairs:
  require(k not in out,'duplicate field');out[k]=v
 return out
def decode(raw):return json.loads(raw,object_pairs_hook=unique)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def selected():
 # Manifest and referenced configs are root-protected; only the active intent
 # selects the generation, never a request or command-line selector.
 raw=old.read(REG,0o644,maxsize=65536);reg=decode(raw)
 require(isinstance(reg,dict) and set(reg)=={'schema','active_intent','entries'} and reg['schema']==1 and isinstance(reg['entries'],list) and 1<=len(reg['entries'])<=16,'registry unavailable')
 matches=[];names=set()
 for e in reg['entries']:
  require(isinstance(e,dict) and set(e)=={'config','evidence','config_sha256','evidence_sha256','catalog_sha256'},'registry entry unavailable')
  for key in ('config','evidence'):
   require(isinstance(e[key],str) and re.fullmatch(r'[A-Za-z0-9_-]+\.json',e[key]) and e[key] not in names,'registry path unavailable');names.add(e[key])
  cfg=decode(old.read(ROOT/e['config'],0o644,e['config_sha256'],65536));old.read(ROOT/e['evidence'],0o644,e['evidence_sha256'],65536)
  if cfg.get('intent_id')==reg['active_intent']:
   require(cfg.get('launch_scope',{}).get('catalog_sha256')==e['catalog_sha256'],'catalog fingerprint changed');matches.append(cfg)
 require(len(matches)==1,'active catalog unavailable');cfg=matches[0];scope=cfg['launch_scope'];g=scope.get('generation')
 require(isinstance(g,str) and provenance.ID.fullmatch(g) and scope.get('intent_id')==reg['active_intent'] and scope.get('task_id')==cfg.get('task_id'),'active generation unavailable')
 return g,sha(raw),scope

def trusted_ancestry(path):
 fd=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for part in ('',*path.parts[1:]):
   if part:
    nxt=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=nxt
   st=os.fstat(fd);require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and st.st_gid==0 and not st.st_mode&0o022,'untrusted ancestor')
   for attr in ('system.posix_acl_access','system.posix_acl_default'):
    try:os.getxattr('/proc/self/fd/'+str(fd),attr)
    except OSError as e:require(e.errno==errno.ENODATA,'ancestor ACL unavailable')
    else:raise RuntimeError('ancestor ACL present')
 finally:os.close(fd)

def _plan():
 trusted_ancestry(ROOT);trusted_ancestry(STATE)
 require(os.geteuid()==0,'root required');g,registry_sha,scope=selected();source=STATE/'stop'/(g+'.reconcile-snapshot');dest=STATE/'evaluator'/g;receipt_path=STATE/'stop'/(g+'.reconcile-complete.json')
 for path in (ROOT,STATE,STATE/'stop',STATE/'evaluator',source):old.directory(path,0,0,0o700 if path==source else (0o711 if path in (ROOT,STATE) else 0o700))
 require(not os.path.lexists(dest) and not os.path.lexists(ROOT/(g+'.evaluator-snapshot-started.json')),'evaluator already attempted')
 receipt_raw=old.read(receipt_path,0o600);receipt=decode(receipt_raw)
 require(set(os.listdir(source))=={'hello.py','test_hello.py','writer-result.json','relay-done.json','manifest.json'},'snapshot entries unavailable')
 manifest_raw=old.read(source/'manifest.json',0o600);manifest=decode(manifest_raw);writer=old.read(source/'writer-result.json',0o600,maxsize=2048);relay=old.read(source/'relay-done.json',0o600,maxsize=16384)
 files={name:old.read(source/name,0o600,maxsize=8192) for name in provenance.FILES};hashes=provenance.validate(g,receipt,manifest,writer,relay,files)
 w=decode(writer);r=decode(relay);require(w=={'status':'executed','digests':hashes} and r.get('schema')==1 and r.get('generation')==g and r.get('binding_sha256')==receipt['binding_sha256'] and r.get('phase')=='done' and isinstance(r.get('observations'),list) and len(r['observations'])==2,'execution evidence unavailable')
 cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+g.lower()+'.slice');task=decode(old.read(ROOT/'tasks'/(g+'.json'),0o600));st=cg.stat();events=(cg/'cgroup.events').read_text().splitlines();require((st.st_dev,st.st_ino)==(task['cgroup_dev'],task['cgroup_ino']) and events.count('frozen 1')==1 and events.count('populated 0')==1,'generation cgroup unavailable')
 return {'generation':g,'task':scope['task_id'],'registry_sha256':registry_sha,'reconcile_sha256':sha(receipt_raw),'manifest_sha256':sha(manifest_raw),'candidate_sha256':hashes,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'scope':'production snapshot only; no service or challenge'}
def plan():
 with gate.admission():return _plan()
def apply(reviewed):
 with gate.admission():return _apply(reviewed)
def _apply(reviewed):
 require(_plan()==reviewed,'snapshot plan changed');g=reviewed['generation'];source=STATE/'stop'/(g+'.reconcile-snapshot');parent=STATE/'evaluator';dest=parent/g;intent=ROOT/(g+'.evaluator-snapshot-started.json');old.store(intent,json.dumps(reviewed,sort_keys=True).encode()+b'\n',0o600)
 data={n:old.read(source/n,0o600,maxsize=8192) for n in provenance.FILES}
 require({k:sha(v) for k,v in data.items()}==reviewed['candidate_sha256'],'candidate changed')
 os.mkdir(dest,0o700);os.chmod(dest,0o700);old.syncdir(parent);broker=dest/'broker';os.mkdir(broker,0o700);os.chmod(broker,0o700);old.syncdir(dest);snap=dest/'snapshot';os.mkdir(snap,0o755);os.chmod(snap,0o755)
 for name,value in data.items():old.store(snap/name,value,0o444)
 os.chmod(snap,0o555);old.syncdir(snap);old.syncdir(dest)
 st=snap.stat();result={'generation':g,'reconcile_sha256':reviewed['reconcile_sha256'],'manifest_sha256':reviewed['manifest_sha256'],'candidate_sha256':reviewed['candidate_sha256'],'snapshot_dev':st.st_dev,'snapshot_ino':st.st_ino,'fixture_only':False};old.store(ROOT/(g+'.evaluator-snapshot-complete.json'),json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
