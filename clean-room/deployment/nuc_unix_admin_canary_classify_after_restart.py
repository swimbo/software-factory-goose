"""Classify fixed synthetic work after the owned Restate restart."""
import hashlib,json,os,re
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_start_v4_old as start
import nuc_ingress_fence_assertions as check
ROOT=old.ETC;OUT=ROOT/'unix-admin-canary-after-restart-journal.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def read(name, maxsize=65536):
 raw=old.read(ROOT/name,0o600,maxsize=maxsize);return raw,json.loads(raw)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def plan():
 require(os.geteuid()==0 and not os.path.lexists(OUT),'classification occupied')
 rr,restart=read('unix-admin-canary-restate-restart-complete.json');epoch=restart.get('epoch3');require(restart.get('schema')==1 and restart.get('old_restart_refused') is True and restart.get('history_replayed') is False and isinstance(epoch,dict),'restart unavailable');start.verify_epoch(epoch,allow_registered=True)
 er,_=read('unix-admin-canary-epoch2-complete.json');require(restart.get('epoch2_sha256')==sha(er),'prior epoch changed')
 braw,b=read('unix-admin-canary-before-retirement.json');araw,a=read('unix-admin-canary-after-retirement.json');jraw,j=read('unix-admin-canary-after-journal.json');regraw,reg=read('unix-admin-canary-v4-register-old-complete.json');nraw,n=read('unix-admin-canary-snapshot-reconcile-complete.json')
 require(b.get('epoch_sha256')==sha(er) and a.get('epoch_sha256')==sha(er) and j.get('epoch_sha256')==sha(er) and j.get('after_probe_sha256')==sha(araw) and j.get('classification')=={'forwarded':'retained-nonterminal','old_effect':'absent'},'prior evidence changed')
 ids=n.get('result',{}).get('ids');oldid=reg.get('deployment_id');require(n.get('role')=='reconcile' and n.get('epoch_sha256')==sha(er) and isinstance(ids,list) and len(ids)==1 and isinstance(ids[0],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',ids[0]) and restart.get('old_deployment_id')==oldid and restart.get('new_deployment_id')==ids[0] and oldid!=ids[0],'deployment evidence unavailable')
 baseraw,base=read('unix-admin-canary-snapshot-baseline-complete.json',196608);_,bj=read('unix-admin-canary-before-journal.json');require(bj.get('snapshot_sha256')==sha(baseraw) and base.get('role')=='baseline' and base.get('epoch_sha256')==sha(er) and base.get('result',{}).get('operation')=='snapshot','baseline snapshot unavailable')
 sraw,s=read('unix-admin-canary-snapshot-afterrestart-complete.json',196608);require(s.get('role')=='afterrestart' and s.get('epoch_sha256')==sha(rr) and s.get('result',{}).get('operation')=='snapshot','restart snapshot unavailable')
 rows=s['result'].get('rows',{});classification=check.classify_after_restart(rows.get('invocations'),rows.get('state'),b['hold'],b['queued'],a['forwarded'],oldid,ids[0],base['result'].get('rows',{}).get('invocations'))
 classification['completed_history']=check.compare_completed_history(base['result'].get('rows',{}).get('invocations'),rows.get('invocations'),oldid)
 queue=rows.get('queue');require(isinstance(queue,list) and len(queue)<=100,'queue unavailable')
 for invocation in (b['hold'],b['queued']):
  matches=[q for q in queue if isinstance(q,dict) and q.get('entry_id')==invocation];require(len(matches)==1 and matches[0].get('entry_kind')=='invocation' and matches[0].get('deployment') in (None,oldid),'queue history unavailable')
 return {'schema':1,'restart_sha256':sha(rr),'prior_journal_sha256':sha(jraw),'after_probe_sha256':sha(araw),'snapshot_sha256':sha(sraw),'old_deployment_id':oldid,'new_deployment_id':ids[0],'classification':classification}
def apply(reviewed):
 require(plan()==reviewed,'restart classification changed');old.store(OUT,json.dumps(reviewed,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return reviewed
