#!/usr/bin/python3
"""Native, read-only Restate drain observation; caller supplies root-pinned IDs.

Zero counts are only a snapshot; an independently enforced ingress fence is
still required before any transition can consume the observation.
"""
import http.client,json,os,re,sys
SERVICES=('ClaimLeaseJournal','RuntimeIntakeJournal','WorkerQueueJournal','IntakeJournal')
TABLES=('sys_vqueues','sys_vqueue_entry_status')
def require(v,m):
 if not v:raise RuntimeError(m)
def main():
 require((os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2000,2000,2000,2000),'identity')
 status=open('/proc/self/status').read();require('NoNewPrivs:\t1' in status and all(('Cap'+x+':\t0000000000000000') in status for x in ('Inh','Prm','Eff','Bnd','Amb')),'capabilities')
 raw=sys.stdin.buffer.read(4097);require(len(raw)<=4096,'input bound');value=json.loads(raw)
 require(set(value)=={'schema','deployment_ids'} and type(value['schema']) is int and value['schema']==1 and isinstance(value['deployment_ids'],list) and 1<=len(value['deployment_ids'])<=16 and len(value['deployment_ids'])==len(set(value['deployment_ids'])) and all(isinstance(x,str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',x) for x in value['deployment_ids']),'invalid deployments')
 ids=','.join("'"+x+"'" for x in value['deployment_ids']);services=','.join("'"+x+"'" for x in SERVICES)
 queries={'invocations':f"SELECT COUNT(*) AS n FROM sys_invocation_status WHERE target_service_name IN ({services}) AND (pinned_deployment_id IS NULL OR pinned_deployment_id IN ({ids}))"}
 for table in TABLES:queries[table]=f"SELECT COUNT(*) AS n FROM {table} WHERE deployment IS NULL OR deployment IN ({ids})"
 result={}
 for name,q in queries.items():
  c=http.client.HTTPConnection('127.0.0.1',9070,timeout=10)
  try:
   c.request('POST','/query',json.dumps({'query':q}),{'Content-Type':'application/json','Accept':'application/json'});r=c.getresponse();body=r.read(4097)
   require(r.status==200 and len(body)<=4096,'query unavailable');obj=json.loads(body)
   require(isinstance(obj,dict) and set(obj)=={'rows'} and isinstance(obj['rows'],list) and len(obj['rows'])==1 and set(obj['rows'][0])=={'n'},'query result invalid');n=obj['rows'][0]['n'];require(type(n) is int and n>=0,'count invalid');result[name]=n
  finally:c.close()
 print(json.dumps({'schema':1,'counts':result},sort_keys=True,separators=(',',':')))
if __name__=='__main__':main()
