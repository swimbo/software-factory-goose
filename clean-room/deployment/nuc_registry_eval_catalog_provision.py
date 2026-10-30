"""Create-only production evaluator challenge catalog; no service activation."""
import hashlib,json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_eval_backend_v3 as backend
import nuc_registry_eval_snapshot_provision as snapshot
import nuc_registry_transition_gate as gate
ROOT=old.ETC;STATE=pathlib.Path('/var/lib/software-factory-goose');ALPH='0123456789ABCDEFGHJKMNPQRSTVWXYZ'
def require(v,m):
 if not v:raise RuntimeError(m)
def canon(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def target(g,i):
 n=int.from_bytes(hashlib.sha256(('sfactory-production-evaluator-v1:'+g+':'+str(i)).encode()).digest()[:16],'big')
 return ''.join(ALPH[(n>>s)&31] for s in range(125,-1,-5))
def _plan():
 snapshot.trusted_ancestry(ROOT);snapshot.trusted_ancestry(STATE);g,registry_sha,scope=snapshot.selected()
 complete=ROOT/(g+'.evaluator-snapshot-complete.json');raw=old.read(complete,0o600);record=snapshot.decode(raw)
 require(record.get('generation')==g and record.get('fixture_only') is False and set(record.get('candidate_sha256',{}))==set(snapshot.provenance.FILES),'snapshot receipt unavailable')
 snap=STATE/'evaluator'/g/'snapshot';st=snap.stat();entry={'snapshot_path':str(snap),'snapshot_dev':record['snapshot_dev'],'snapshot_ino':record['snapshot_ino'],'generation':g}
 require((st.st_dev,st.st_ino)==(record['snapshot_dev'],record['snapshot_ino']) and backend.verify_snapshot(entry,old.noacl)==record['candidate_sha256'],'snapshot unavailable')
 receipt=old.read(STATE/'stop'/(g+'.reconcile-complete.json'),0o600,record['reconcile_sha256']);require(snapshot.decode(receipt).get('generation')==g,'reconciliation changed')
 catalog=ROOT/(g+'.evaluator-catalog.json');intent=ROOT/(g+'.evaluator-catalog-started.json');done=ROOT/(g+'.evaluator-catalog-complete.json')
 require(not any(os.path.lexists(p) for p in (catalog,intent,done)),'catalog occupied')
 old.directory(ROOT/'tasks',0,0,0o700)
 paths=subprocess.run(['/usr/bin/systemd-analyze','--system','unit-paths'],env=old.ENV,capture_output=True,timeout=5,check=True).stdout.decode().splitlines();require(paths and len(paths)<=64 and all(pathlib.Path(p).is_absolute() for p in paths),'unit paths unavailable')
 ids=[target(g,i) for i in range(1,23)];require(len(set(ids))==22 and g not in ids,'target collision')
 for tid in ids:
  unit='sfactory'+tid.lower()+'.slice'
  for p in (ROOT/'tasks'/(tid+'.json'),ROOT/'tasks'/(tid+'.create-intent.json'),old.UNIT/unit,pathlib.Path('/sys/fs/cgroup')/unit):require(not os.path.lexists(p),'target occupied')
  require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found' and old.ctl('show',unit,'-p','DropInPaths','--value')=='','target loaded')
  for parent in paths:
   for name in [unit,unit+'.d','slice.d']+[unit[:i+1]+'slice.d' for i,c in enumerate(unit[:-6]) if c=='-']:require(not os.path.lexists(pathlib.Path(parent)/name),'unit path occupied')
 return {'generation':g,'task':scope['task_id'],'registry_sha256':registry_sha,'snapshot_receipt_sha256':hashlib.sha256(raw).hexdigest(),'reconcile_sha256':record['reconcile_sha256'],'candidate_sha256':record['candidate_sha256'],'snapshot_dev':st.st_dev,'snapshot_ino':st.st_ino,'targets':ids,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'scope':'catalog and empty slices only; no evaluation'}
def plan():
 with gate.admission():return _plan()
def apply(reviewed):
 with gate.admission():return _apply(reviewed)
def _apply(reviewed):
 require(_plan()==reviewed,'catalog plan changed');g=reviewed['generation'];intent=ROOT/(g+'.evaluator-catalog-started.json');done=ROOT/(g+'.evaluator-catalog-complete.json');old.store(intent,canon(reviewed),0o600)
 unit_text=b'[Unit]\nDescription=Software factory evaluator challenge\n[Slice]\nMemoryMax=128M\nTasksMax=32\nCPUQuota=50%\n'
 for tid in reviewed['targets']:old.store(old.UNIT/('sfactory'+tid.lower()+'.slice'),unit_text,0o644)
 old.ctl('daemon-reload');entries=[]
 for tid in reviewed['targets']:
  name='sfactory'+tid.lower()+'.slice'
  for k,v in (('LoadState','loaded'),('Names',name),('FragmentPath',str(old.UNIT/name)),('DropInPaths',''),('NeedDaemonReload','no'),('Job','')):require(old.ctl('show',name,'-p',k,'--value')==v,'slice identity changed')
  old.store(ROOT/'tasks'/(tid+'.create-intent.json'),canon({'generation':g,'target':tid}),0o600);old.ctl('start',name)
  cg=pathlib.Path('/sys/fs/cgroup')/name;st=cg.stat();q=(cg/'cpu.max').read_text().split();events=(cg/'cgroup.events').read_text().splitlines()
  require(st.st_uid==0 and st.st_gid==0 and events.count('populated 0')==1 and events.count('frozen 0')==1 and (cg/'memory.max').read_text().strip()==str(128*1024**2) and (cg/'pids.max').read_text().strip()=='32' and len(q)==2 and all(x.isdigit() for x in q) and 2*int(q[0])==int(q[1]),'slice limits unavailable')
  task={'schema':1,'target_id':tid,'task_id':g,'generation':tid,'boot_id':reviewed['boot_id'],'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino};old.store(ROOT/'tasks'/(tid+'.json'),canon(task),0o600)
  entries.append({'target':tid,'task_id':g,'generation':g,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'snapshot_path':str(STATE/'evaluator'/g/'snapshot'),'snapshot_dev':reviewed['snapshot_dev'],'snapshot_ino':reviewed['snapshot_ino']})
 catalog={'schema':1,'generation':g,'snapshot_sha256':reviewed['candidate_sha256'],'challenges':entries,'boot_id':reviewed['boot_id'],'reconcile_sha256':reviewed['reconcile_sha256']};data=canon(catalog);old.store(ROOT/(g+'.evaluator-catalog.json'),data,0o600)
 result={'generation':g,'catalog_sha256':hashlib.sha256(data).hexdigest(),'targets':len(entries),'fixture_only':False,'services_started':False};old.store(done,canon(result),0o600);return result
