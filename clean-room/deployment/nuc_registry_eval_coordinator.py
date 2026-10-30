#!/usr/bin/python3
"""Fixed private UID2002 holdout controller; installation/attestation required."""
import json,os,sys
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/evaluator')
from nuc_registry_evaluator import EvaluationUnavailable,UnixBroker,evaluate
from nuc_registry_eval_client import DIR,connect,read,verify,noacl

def main():
 if os.getuid()!=2002 or os.geteuid()!=2002 or len(sys.argv)!=1:raise EvaluationUnavailable('coordinator unavailable')
 root=os.open(DIR,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(root);noacl(root,True)
  if (st.st_uid,st.st_gid,st.st_mode&0o777)!=(0,2002,0o710):raise EvaluationUnavailable('coordinator unavailable')
  fd=os.open('scope.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=root)
  try:raw=read(fd,0o440,2002,8192)
  finally:os.close(fd)
 finally:os.close(root)
 def unique(pairs):
  out={}
  for k,v in pairs:
   if k in out:raise EvaluationUnavailable('scope unavailable')
   out[k]=v
  return out
 scope=json.loads(raw,object_pairs_hook=unique)
 if not isinstance(scope,dict) or set(scope)!={'schema','generation','candidate_sha256'} or type(scope['schema']) is not int or scope['schema']!=1:raise EvaluationUnavailable('scope unavailable')
 generation=scope['generation'];identity=lambda:verify(generation)
 result=evaluate(scope['candidate_sha256'],UnixBroker(connect,identity),generation)
 print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
if __name__=='__main__':
 try:main()
 except Exception:
  print('evaluation unavailable',file=sys.stderr);raise SystemExit(1)
