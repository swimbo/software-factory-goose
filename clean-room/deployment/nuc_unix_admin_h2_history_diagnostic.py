"""Fixed bounded synthetic history-result encoding diagnostic; no query."""
import hashlib,json,os
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
DONE=old.ETC/'unix-admin-h2-canary-history-diagnostic.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'diagnostic occupied')
 raw=old.read(old.ETC/'unix-admin-h2-canary-snapshot-baseline-complete.json',0o600,maxsize=196608);s=json.loads(raw);d=json.loads(old.read(old.ETC/'unix-admin-h2-canary-baseline-diagnostic.json',0o600,maxsize=196608));require(s.get('role')=='baseline' and d.get('snapshot_sha256')==base.sha(raw),'snapshot binding unavailable')
 rows=s['result']['rows']['invocations'];matches=[x for x in rows if x.get('target_service_name')=='FenceFixture' and x.get('target_service_key')=='history' and x.get('target_handler_name')=='increment'];require(len(matches)==1,'history unavailable');v=matches[0].get('completion_result')
 result={'schema':1,'snapshot_sha256':base.sha(raw),'type':type(v).__name__,'exact_expected':False,'marker':None,'object_keys':[],'public_version':None,'public_count':None,'value_sha256':None}
 if isinstance(v,str):
  require(len(v.encode())<=4096,'result oversized');result['value_sha256']=hashlib.sha256(v.encode()).hexdigest()
  if v in ('success','failure'):result['marker']=v
  try:parsed=json.loads(v)
  except (ValueError,TypeError):parsed=None
 elif isinstance(v,dict):parsed=v
 else:parsed=None
 if isinstance(parsed,dict):
  result['object_keys']=sorted(str(x) for x in parsed) if all(isinstance(x,str) and len(x)<80 and x.isascii() for x in parsed) else ['<other>']
  if parsed.get('version') in ('old','new'):result['public_version']=parsed['version']
  if type(parsed.get('count')) is int and 0<=parsed['count']<=100:result['public_count']=parsed['count']
  result['exact_expected']=parsed=={'version':'old','count':1}
 return result
def apply(approved):
 require(plan()==approved,'diagnostic changed');old.store(DONE,base.canonical(approved)+b'\n',0o600);return approved
