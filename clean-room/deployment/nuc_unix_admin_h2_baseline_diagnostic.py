"""Summarize only fixed synthetic baseline row structure; never query or invoke."""
import json,os,re
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
DONE=old.ETC/'unix-admin-h2-canary-baseline-diagnostic.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def read(name,limit=196608):
 raw=old.read(old.ETC/name,0o600,maxsize=limit);return raw,json.loads(raw)
def safe(v):
 if v is None:return None
 if isinstance(v,str) and len(v)<=80 and re.fullmatch(r'[A-Za-z0-9_.-]+',v):return v
 return '<other>'
def kind(v):return 'null' if v is None else 'string' if isinstance(v,str) else 'number' if type(v) in (int,float) else 'object' if isinstance(v,dict) else 'array' if isinstance(v,list) else 'other'
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'diagnostic occupied')
 er,e=read('unix-admin-h2-canary-epoch2-complete.json');br,b=read('unix-admin-h2-canary-before-retirement.json');rr,r=read('unix-admin-h2-canary-register-old-complete.json');sr,s=read('unix-admin-h2-canary-snapshot-baseline-complete.json')
 require(e.get('schema')==1 and b.get('epoch_sha256')==base.sha(er) and s.get('epoch_sha256')==base.sha(er) and s.get('role')=='baseline' and s.get('result',{}).get('operation')=='snapshot' and r.get('operation')=='register-old','receipt binding mismatch')
 hold=b['hold'];queued=b['queued'];deployment=r['deployment_id'];require(isinstance(hold,str) and isinstance(queued,str) and hold!=queued and isinstance(deployment,str),'fixture ids unavailable')
 rows=s['result'].get('rows',{});require(set(rows)=={'invocations','queue','state'} and all(isinstance(v,list) and len(v)<=100 for v in rows.values()),'rows unavailable')
 def mask(value):return 'hold' if value==hold else 'queued' if value==queued else 'other'
 inv=[]
 for x in rows['invocations']:
  require(isinstance(x,dict),'invocation invalid');inv.append({'keys':sorted(safe(k) for k in x),'id_match':mask(x.get('id')),'service':safe(x.get('target_service_name')),'handler':safe(x.get('target_handler_name')),'key':safe(x.get('target_service_key')),'status':safe(x.get('status')),'deployment':'old' if x.get('pinned_deployment_id')==deployment else 'null' if x.get('pinned_deployment_id') is None else 'other','scheduled_type':kind(x.get('scheduled_start_at')),'result_type':kind(x.get('completion_result'))})
 queue=[]
 for x in rows['queue']:
  require(isinstance(x,dict),'queue invalid');queue.append({'keys':sorted(safe(k) for k in x),'id_match':mask(x.get('entry_id')),'entry_kind':safe(x.get('entry_kind')),'status':safe(x.get('status')),'stage':safe(x.get('stage')),'deployment':'old' if x.get('deployment')==deployment else 'null' if x.get('deployment') is None else 'other'})
 counters=[]
 for x in rows['state']:
  require(isinstance(x,dict) and x.get('key')=='count' and x.get('service_key') in ('history','scheduler','blocked','delayed','after'),'counter invalid');v=json.loads(x['value_utf8']);require(type(v) is int and 0<=v<=100,'counter value invalid');counters.append({'key':x['service_key'],'value':v})
 return {'schema':1,'epoch_sha256':base.sha(er),'snapshot_sha256':base.sha(sr),'probe_sha256':base.sha(br),'registration_sha256':base.sha(rr),'invocations':inv,'queue':queue,'counters':counters,'scope':'sanitized retained synthetic baseline; no query'}
def apply(approved):
 require(plan()==approved,'diagnostic changed');old.store(DONE,base.canonical(approved)+b'\n',0o600);return approved
