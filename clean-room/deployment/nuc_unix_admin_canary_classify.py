"""Create-only root classification of actual bounded synthetic Restate snapshots."""
import hashlib,json,os,re
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_probe_start as probe
import nuc_ingress_fence_assertions as check
ROLE=None
ETC=old.ETC
BEFORE=ETC/'unix-admin-canary-before-retirement.json';AFTER=ETC/'unix-admin-canary-after-retirement.json';REG=ETC/'unix-admin-canary-v4-register-old-complete.json'
JOURNAL_BEFORE=ETC/'unix-admin-canary-before-journal.json';JOURNAL_AFTER=ETC/'unix-admin-canary-after-journal.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def read(path, maxsize=65536):
 raw=old.read(path,0o600,maxsize=maxsize);return raw,json.loads(raw)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def counters(snapshot):
 rows=snapshot.get('rows',{}).get('state');require(isinstance(rows,list) and len(rows)<=100,'counter state unavailable')
 values={}
 for row in rows:
  require(isinstance(row,dict) and row.get('key')=='count' and isinstance(row.get('service_key'),str) and row['service_key'] not in values,'counter state malformed')
  values[row['service_key']]=json.loads(row['value_utf8'])
 require(values=={'history':1},'counter state not baseline')
 return values
def _plan():
 require(os.geteuid()==0 and ROLE in ('baseline','postretire'),'role unavailable');out=JOURNAL_BEFORE if ROLE=='baseline' else JOURNAL_AFTER;require(not os.path.lexists(out),'classification occupied')
 epoch=probe.epoch();braw,b=read(BEFORE);_,reg=read(REG);require(b.get('epoch_sha256')==epoch and reg.get('operation')=='register-old' and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',reg.get('deployment_id','')),'scope unavailable')
 sraw,s=read(ETC/('unix-admin-canary-snapshot-'+ROLE+'-complete.json'),196608);require(s.get('schema')==1 and s.get('role')==ROLE and s.get('epoch_sha256')==epoch and s.get('result',{}).get('operation')=='snapshot','snapshot unavailable')
 payload=s['result'];rows=payload.get('rows',{}).get('invocations');classification=check.classify(rows,b['hold'],b['queued'],reg['deployment_id']);counters(payload)
 queue=payload.get('rows',{}).get('queue');require(isinstance(queue,list) and len(queue)<=100,'queue unavailable')
 for inv in (b['hold'],b['queued']):
  matches=[q for q in queue if isinstance(q,dict) and q.get('entry_id')==inv];require(len(matches)==1 and matches[0].get('entry_kind')=='invocation' and matches[0].get('deployment') in (None,reg['deployment_id']),'queue identity unavailable')
 if ROLE=='baseline':return {'schema':1,'epoch_sha256':epoch,'old_deployment_id':reg['deployment_id'],'probe_receipt_sha256':sha(braw),'snapshot_sha256':sha(sraw),'classification':classification}
 base_raw,baseline=read(JOURNAL_BEFORE);araw,after=read(AFTER);require(baseline.get('epoch_sha256')==epoch and baseline.get('old_deployment_id')==reg['deployment_id'] and baseline.get('probe_receipt_sha256')==sha(braw) and after.get('epoch_sha256')==epoch and after.get('stage')=='after_retirement' and after.get('effect')=='requires journal inspection' and after.get('old_connection_denied') is True and after.get('new_connection_denied') is True and after.get('probe_terminal') is True,'after scope unavailable')
 matches=[x for x in rows if x.get('id')==after['forwarded']];require(len(matches)==1,'forwarded invocation unavailable');item=matches[0];require(item.get('target_service_name')=='FenceFixture' and item.get('target_service_key')=='after' and item.get('target_handler_name')=='increment' and item.get('status') in check.NONTERMINAL and item.get('pinned_deployment_id') in (None,reg['deployment_id']),'forwarded outcome unavailable')
 return {'schema':1,'epoch_sha256':epoch,'after_probe_sha256':sha(araw),'snapshot_sha256':sha(sraw),'classification':{'forwarded':'retained-nonterminal','old_effect':'absent'}}
def plan():return _plan()
def apply(reviewed):
 require(plan()==reviewed,'classification changed');path=JOURNAL_BEFORE if ROLE=='baseline' else JOURNAL_AFTER;old.store(path,json.dumps(reviewed,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return reviewed
