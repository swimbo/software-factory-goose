"""One-shot SDK5 registration participant; caller holds the transition EX lock.

A previously committed start record always prevents another registration. A
failure, timeout or unverified response leaves that record and pending marker.
"""
import hashlib,json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_v5_install as install
# Must be replaced by the digest of a reviewed, fixed old-deployment drain producer.
DRAIN_PRODUCER_SHA=None
DRAIN_PRODUCER=None
UNIT=install.NAME+'register.service'
def require(v,msg):
 if not v:raise RuntimeError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def binding(intent):
 require(DRAIN_PRODUCER_SHA is not None and DRAIN_PRODUCER is not None,'reviewed old SDK drain producer unavailable')
 require(sha(gate._protected_read(DRAIN_PRODUCER,0o755,1_000_000))==DRAIN_PRODUCER_SHA,'drain producer changed')
 name=intent['transition_id'];require(isinstance(name,str) and re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',name),'transition identity unavailable')
 require(gate._json(gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000))==intent,'pending transition changed')
 hist=gate.ROOT/'history';plan_raw=gate._protected_read(hist/(name+'.plan.json'),0o600,16384);plan=gate._json(plan_raw)
 require(plan.get('transition_id')==name and plan.get('old_manifest_sha256')==intent['old_manifest_sha256'] and plan.get('new_manifest_sha256')==intent['new_manifest_sha256'] and plan.get('new_sdk_uri')=='http://127.0.0.1:9085','transition plan changed')
 drain_raw=gate._protected_read(hist/(name+'.drain.json'),0o600,16384);drain=gate._json(drain_raw)
 require(set(drain)=={'schema','transition_id','producer_sha256','old_manifest_sha256','old_deployment_id','drained','ingress_fenced'} and drain=={'schema':1,'transition_id':name,'producer_sha256':DRAIN_PRODUCER_SHA,'old_manifest_sha256':intent['old_manifest_sha256'],'old_deployment_id':plan['old_deployment_id'],'drained':True,'ingress_fenced':True},'old SDK drain unproven')
 require(sha(gate._protected_read(gate.REGISTRY,0o644,65536))==intent['new_manifest_sha256'],'new manifest changed')
 old.read(install.BIN,0o755,install.SOURCE_SHA,100_000_000);old.read(install.REGISTER,0o755,sha(install.REGISTER_SOURCE));unit=install.units()[UNIT];old.read(old.UNIT/UNIT,0o644,sha(unit))
 p=props();require(p.get('LoadState')=='loaded' and p.get('Names')==UNIT and p.get('FragmentPath')==str(old.UNIT/UNIT) and p.get('DropInPaths','')=='' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='','registration unit unavailable')
 require(not os.path.lexists(hist/(name+'.registration-started.json')) and not os.path.lexists(hist/(name+'.registration-complete.json')),'registration already attempted')
 return {'schema':1,'transition_id':name,'plan_sha256':sha(plan_raw),'drain_sha256':sha(drain_raw),'new_manifest_sha256':intent['new_manifest_sha256'],'uri':'http://127.0.0.1:9085'}
def props():
 raw=old.ctl('show',UNIT,'--property=LoadState,ActiveState,MainPID,Job,Names,FragmentPath,DropInPaths,Result,ExecMainStatus,InvocationID','--all','--no-pager')
 return dict(line.split('=',1) for line in raw.splitlines())
def run(intent,approved):
 require(binding(intent)==approved,'registration binding changed');name=intent['transition_id'];hist=gate.ROOT/'history'
 gate._store_history(hist,name+'.registration-started.json',canonical(approved)+b'\n')
 p=subprocess.run(['/usr/bin/systemctl','start',UNIT],env=old.ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,check=False)
 require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'registration outcome unknown')
 state=props();inv=state.get('InvocationID','');require(state.get('ActiveState')=='inactive' and state.get('MainPID')=='0' and state.get('Job','')=='' and state.get('Result')=='success' and state.get('ExecMainStatus')=='0' and re.fullmatch(r'[0-9a-f]{32}',inv),'registration terminal status unknown')
 p=subprocess.run(['/usr/bin/journalctl','--boot','-u',UNIT,'--no-pager','-o','json','--output-fields=MESSAGE,_SYSTEMD_INVOCATION_ID'],env=old.ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=False)
 require(p.returncode==0 and len(p.stdout)<=65536 and len(p.stderr)<=8192,'registration journal unavailable');matches=[]
 for line in p.stdout.splitlines():
  item=gate._json(line);msg=item.get('MESSAGE')
  if item.get('_SYSTEMD_INVOCATION_ID')==inv and isinstance(msg,str) and msg.startswith('REGISTRY_V5_REGISTRATION '):matches.append(gate._json(msg.removeprefix('REGISTRY_V5_REGISTRATION ').encode()))
 require(len(matches)==1 and set(matches[0])=={'id','service_count'} and matches[0]['service_count']==4 and isinstance(matches[0]['id'],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',matches[0]['id']),'registration reply unknown')
 result={'schema':1,'transition_id':name,'uri':'http://127.0.0.1:9085','deployment_id':matches[0]['id'],'invocation_id':inv,'binding_sha256':sha(canonical(approved)+b'\n')}
 gate._store_history(hist,name+'.registration-complete.json',canonical(result)+b'\n');return result
