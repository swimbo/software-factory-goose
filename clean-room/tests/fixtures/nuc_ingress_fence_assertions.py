"""Assertions over bounded real Restate fixture query results; no queries or effects."""
NONTERMINAL={'invoked','pending','scheduled','inboxed','ready','running','suspended','backing-off','paused'}
def require(v,m):
 if not v:raise RuntimeError(m)
def classify(rows,hold_id,queued_id,old_deployment,delayed_id=None):
 require(isinstance(rows,list) and len(rows)<=128 and isinstance(hold_id,str) and hold_id and isinstance(queued_id,str) and queued_id and hold_id!=queued_id and isinstance(old_deployment,str) and old_deployment.startswith('dp_'),'fixture scope unavailable')
 require(all(isinstance(row,dict) for row in rows),'invalid journal rows')
 def exact(inv):
  found=[r for r in rows if r.get('id')==inv];require(len(found)==1,'invocation unavailable');return found[0]
 hold=exact(hold_id);queued=exact(queued_id)
 for row,handler in ((hold,'hold'),(queued,'increment')):
  require(row.get('target_service_name')=='FenceFixture' and row.get('target_service_key')=='blocked' and row.get('target_handler_name')==handler and row.get('status') in NONTERMINAL,'work classification unavailable')
 require(hold.get('pinned_deployment_id')==old_deployment,'hold deployment unavailable')
 require(queued.get('pinned_deployment_id') in (None,old_deployment),'queued deployment changed')
 delayed=[r for r in rows if r.get('target_service_name')=='FenceFixture' and r.get('target_service_key')=='delayed' and r.get('target_handler_name')=='increment']
 require(len(delayed)==1 and isinstance(delayed[0].get('id'),str) and delayed[0].get('id') and delayed[0].get('pinned_deployment_id') in (None,old_deployment),'scheduled work unavailable')
 if delayed_id is None:
  require(delayed[0].get('status')=='scheduled','scheduled work unavailable');delayed_state='scheduled'
 else:
  require(delayed[0]['id']==delayed_id and delayed[0].get('status') in NONTERMINAL,'delayed work identity or status changed')
  delayed_state='scheduled' if delayed[0]['status']=='scheduled' else 'retained-nonterminal-matured'
 return {'hold':'old-pinned-nonterminal','queued':'retained-nonterminal','delayed':delayed_state,'all_drained':False}

def classify_after_restart(rows,state,hold_id,queued_id,forwarded_id,old_deployment,new_deployment,baseline_rows):
 import json
 baseline=classify(baseline_rows,hold_id,queued_id,old_deployment)
 require(baseline['delayed']=='scheduled','baseline delayed work unavailable')
 delayed=[r for r in baseline_rows if r.get('target_service_name')=='FenceFixture' and r.get('target_service_key')=='delayed' and r.get('target_handler_name')=='increment']
 prior=classify(rows,hold_id,queued_id,old_deployment,delayed[0]['id'])
 require(isinstance(new_deployment,str) and new_deployment.startswith('dp_') and new_deployment!=old_deployment,'new deployment unavailable')
 matches=[r for r in rows if r.get('id')==forwarded_id];require(len(matches)==1,'forwarded invocation unavailable');item=matches[0]
 require(item.get('target_service_name')=='FenceFixture' and item.get('target_service_key')=='after' and item.get('target_handler_name')=='increment','forwarded target unavailable')
 require(isinstance(state,list) and len(state)<=100,'state unavailable');values={}
 for r in state:
  require(isinstance(r,dict) and r.get('key')=='count' and isinstance(r.get('service_key'),str) and r['service_key'] not in values,'state malformed')
  values[r['service_key']]=json.loads(r['value_utf8'])
 if item.get('status') in NONTERMINAL:
  require(item.get('pinned_deployment_id') in (None,old_deployment,new_deployment) and values=={'history':1},'pending forwarded state unavailable')
  outcome='retained-nonterminal'
 else:
  result=item.get('completion_result')
  if isinstance(result,str):result=json.loads(result)
  require(item.get('status')=='completed' and item.get('pinned_deployment_id')==new_deployment and result=={'version':'new','count':1} and values=={'history':1,'after':1},'completed forwarded result unavailable')
  outcome='completed-on-new'
 return {'old_work':prior,'forwarded':outcome,'old_effect':'absent'}


def completed_history(rows, old_deployment):
 require(isinstance(rows,list) and len(rows)<=128 and all(isinstance(r,dict) for r in rows),'history rows unavailable')
 matches=[r for r in rows if r.get('target_service_name')=='FenceFixture' and r.get('target_service_key')=='history' and r.get('target_handler_name')=='increment']
 require(len(matches)==1,'completed history unavailable')
 row=matches[0];require(isinstance(row.get('id'),str) and row['id'] and row.get('status')=='completed' and row.get('pinned_deployment_id')==old_deployment and row.get('completion_result')=='success','completed history invalid')
 return row['id']

def compare_completed_history(baseline,after,old_deployment):
 require(completed_history(baseline,old_deployment)==completed_history(after,old_deployment),'completed history changed')
 return 'same-completed-invocation-and-success-status'
