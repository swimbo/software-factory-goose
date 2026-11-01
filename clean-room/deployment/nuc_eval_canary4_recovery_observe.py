"""Persist exact owner-loss/replay observations; no engine or service mutation."""
import hashlib,json,os,pathlib,sys
import nuc_grant_sidecar_install as old
import nuc_eval_canary4_reconcile as recovery
G=recovery.G;ROOT=old.ETC;BASE=recovery.BASE;OUT=ROOT/'evaluator-canary4-ownerloss-observation.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(OUT),'observation occupied')
 spec=recovery.plan()
 native='sfactory-eval-canary4-ownerloss-native.service'
 require(old.ctl('show',native,'-p','MainPID','--value')=='0' and old.ctl('show',native,'-p','ActiveState','--value')=='failed' and old.ctl('show',native,'-p','Result','--value')=='exit-code' and old.ctl('show',native,'-p','Job','--value')=='','native outcome unavailable')
 invocation=old.ctl('show',native,'-p','InvocationID','--value');require(len(invocation)==32 and all(c in '0123456789abcdef' for c in invocation),'native invocation unavailable')
 return {'recovery':spec,'native_invocation':invocation,'scope':'record owner-loss and replay refusal; no engine mutation'}
def apply(reviewed):
 require(plan()==reviewed,'observation plan changed')
 sys.path.insert(0,str(old.PREFIX/'evaluator4'))
 import nuc_registry_eval_canary_runtime as runtime
 import nuc_registry_eval_broker as broker
 runtime.verify_sources()
 class Never:
  calls=0
  def launch_and_reconcile(self,*args):
   self.calls+=1
   raise RuntimeError('unexpected backend call')
 never=Never();fd=os.open(BASE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  raw=old.read(BASE/'01.intent',0o600);req=json.loads(raw);cat=json.loads(old.read(ROOT/'evaluator-canary4-catalog.json',0o600));core=broker.Broker(fd,cat['snapshot_sha256'],never,G,old.noacl)
  try:core.run(2002,req)
  except broker.Unavailable:pass
  else:raise RuntimeError('replay admitted')
  require(never.calls==0 and not os.path.lexists(BASE/'01.done'),'replay reached backend')
 finally:os.close(fd)
 require(plan()==reviewed,'observation changed')
 result={'schema':1,'generation':G,'target':recovery.TARGET,'container_id':recovery.ID,'broker_invocation':'29a5b9acce9f4c2098cc4203ef7155e8','broker_exit_code':2,'broker_signal':9,'native_invocation':reviewed['native_invocation'],'request_sha256':hashlib.sha256(raw).hexdigest(),'replay_backend_calls':0,'done_absent':True,'frozen_empty':True,'result':'unknown'}
 old.store(OUT,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
