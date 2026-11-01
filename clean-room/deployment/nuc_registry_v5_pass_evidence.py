"""Validate independently observed r3 evaluation, Git and exact cleanup evidence.

This is a pure consistency check, not a receipt publisher or filesystem trust
boundary. Its caller must obtain each input independently from protected root
producers and must not promote a candidate as a side effect.
"""
import hashlib,json,re
G='01M66XF6HPBETAJ5V0G45TM8NQ';TASK='01M66XF6HPKEC38CJJP78KQJVC'
HEX=re.compile('[0-9a-f]{64}\\Z');REV=re.compile('(?:[0-9a-f]{40}|[0-9a-f]{64})\\Z')
FILES=('hello.py','test_hello.py')
def require(v):
 if not v:raise ValueError('evaluated pass evidence unavailable')
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def validate(scope,execution,evaluation,challenges,git_observation,files):
 """Inputs are decoded independent observations, never untrusted client claims."""
 require(isinstance(scope,dict) and set(scope)=={'generation','task_id','binding_sha256','boot_id','cgroup_dev','cgroup_ino'} and scope['generation']==G and scope['task_id']==TASK and isinstance(scope['binding_sha256'],str) and HEX.fullmatch(scope['binding_sha256']) is not None and isinstance(scope['boot_id'],str) and type(scope['cgroup_dev']) is int and scope['cgroup_dev']>0 and type(scope['cgroup_ino']) is int and scope['cgroup_ino']>0)
 require(isinstance(files,dict) and set(files)==set(FILES) and all(isinstance(files[k],bytes) and 0<len(files[k])<=8192 for k in FILES));hashes={k:sha(files[k]) for k in FILES};snapshot_sha=sha(canonical({'files':hashes}))
 required={'schema','generation','binding_sha256','writer_id','goose_id','candidate_sha256','kernel_closed_frozen_empty','exact_ids_removed','slice_retained_frozen','engine_reconciled_for_exact_ids'}
 require(isinstance(execution,dict) and set(execution)==required and type(execution['schema']) is int and execution['schema']==1 and execution['generation']==G and execution['binding_sha256']==scope['binding_sha256'] and execution['candidate_sha256']==hashes and all(execution[k] is True for k in ('kernel_closed_frozen_empty','exact_ids_removed','slice_retained_frozen','engine_reconciled_for_exact_ids')) and all(isinstance(execution[k],str) and HEX.fullmatch(execution[k]) for k in ('writer_id','goose_id')) and execution['writer_id']!=execution['goose_id'])
 require(isinstance(evaluation,dict) and set(evaluation)=={'schema','generation','candidate_sha256','scenario_votes','repetitions','candidate_tests','challenges'} and type(evaluation['schema']) is int and evaluation['schema']==1 and evaluation['generation']==G and evaluation['candidate_sha256']==hashes and type(evaluation['repetitions']) is int and evaluation['repetitions']==3 and evaluation['candidate_tests']=='pass' and type(evaluation['challenges']) is int and evaluation['challenges']==22 and isinstance(evaluation['scenario_votes'],list) and len(evaluation['scenario_votes'])==7 and all(type(v) is int and 2<=v<=3 for v in evaluation['scenario_votes']) and sum(evaluation['scenario_votes'])>=19)
 require(isinstance(challenges,list) and len(challenges)==22);seen=set();containers=set()
 for i,c in enumerate(challenges,1):
  require(isinstance(c,dict) and set(c)=={'target','cgroup_dev','cgroup_ino','done','removed','observation'} and isinstance(c['target'],str) and re.fullmatch('[0-7][0-9A-HJKMNP-TV-Z]{25}',c['target']) is not None and c['target'] not in seen and type(c['cgroup_dev']) is int and c['cgroup_dev']>0 and type(c['cgroup_ino']) is int and c['cgroup_ino']>0);seen.add(c['target'])
  d=c['done'];removed=c['removed'];o=c['observation'];require(isinstance(d,dict) and set(d)=={'schema','generation','sequence','intent_sha256','candidate_sha256','container_id','stdout_sha256','stderr_sha256','exit_code'} and type(d['schema']) is int and d['schema']==1 and d['generation']==G and type(d['sequence']) is int and d['sequence']==i and d['candidate_sha256']==hashes and all(isinstance(d[k],str) and HEX.fullmatch(d[k]) for k in ('intent_sha256','container_id','stdout_sha256','stderr_sha256')) and type(d['exit_code']) is int and d['container_id'] not in containers);containers.add(d['container_id'])
  require(isinstance(removed,dict) and set(removed)=={'target','id','frozen_empty'} and removed['target']==c['target'] and removed['id']==d['container_id'] and removed['frozen_empty'] is True)
  require(isinstance(o,dict) and o.get('target_id')==c['target'] and o.get('boot_id')==scope['boot_id'] and (o.get('cgroup_dev'),o.get('cgroup_ino'))==(c['cgroup_dev'],c['cgroup_ino']) and all(o.get(k) is True for k in ('observed','closed','frozen','empty')) and o.get('engine_reconciled') is False)
 require(isinstance(git_observation,dict) and set(git_observation)=={'schema','generation','revision','files','baseline_ancestor','clean_exact_tree'} and type(git_observation['schema']) is int and git_observation['schema']==1 and git_observation['generation']==G and isinstance(git_observation['revision'],str) and REV.fullmatch(git_observation['revision']) and git_observation['files']==hashes and git_observation['baseline_ancestor'] is True and git_observation['clean_exact_tree'] is True)
 return {'generation':G,'task_id':TASK,'binding_sha256':scope['binding_sha256'],'snapshot':{'files':hashes},'snapshot_sha256':snapshot_sha,'revision':git_observation['revision'],'writer_id':execution['writer_id'],'goose_id':execution['goose_id'],'spend':'unknown','promotion':False}
