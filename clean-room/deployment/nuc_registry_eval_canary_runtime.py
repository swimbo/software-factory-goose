#!/usr/bin/python3
"""Synthetic-only evaluator runtime; cannot read the production catalog."""
import hashlib,json,os,pathlib,socket,sys
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/evaluator')
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/relay')
import nuc_grant_sidecar_install as old
import nuc_registry_eval_backend as backend
import nuc_registry_eval_broker as broker
import nuc_registry_eval_deadline as deadline
import nuc_registry_eval_server as server
G='01M65RMR3F04YB1B016EBBSXGK';HELPER_SHA='604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e';PACKAGE_SHA='4cb5a74f7a8027c03edb217b3a5e83ac0af968749cbba6124480c760db8380af'
def main():
 if os.getuid()!=0 or os.geteuid()!=0 or len(sys.argv)!=1:raise broker.Unavailable('canary unavailable')
 fields=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
 if fields.get('NoNewPrivs','').strip()!='1' or any(int(fields[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise broker.Unavailable('canary unavailable')
 old.read(old.ETC/'relay-package.json',0o600,PACKAGE_SHA);raw=old.read(old.PREFIX/'root-launch-host.py',0o755,HELPER_SHA,1_000_000);helper={'__name__':'synthetic_evaluator_helper'};exec(compile(raw,'<pinned-helper>','exec'),helper);base,_=helper['modules']()
 raw_catalog=old.read(old.ETC/'evaluator-canary-catalog.json',0o600,maxsize=65536);cat=json.loads(raw_catalog);receipt=json.loads(old.read(old.ETC/'evaluator-canary-provision-complete.json',0o600))
 if set(cat)!={'schema','purpose','generation','snapshot_sha256','challenges','boot_id'} or cat['schema']!=1 or cat['purpose']!='synthetic-evaluator-canary-only' or cat['generation']!=G or receipt.get('generation')!=G or receipt.get('fixture_only') is not True or receipt.get('catalog_sha256')!=hashlib.sha256(raw_catalog).hexdigest() or cat['boot_id']!=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip():raise broker.Unavailable('canary catalog unavailable')
 cat={k:v for k,v in cat.items() if k!='purpose'}
 if len(cat['challenges'])!=22:raise broker.Unavailable('canary catalog unavailable')
 for item in cat['challenges']:
  if item.get('generation')!=G or backend.verify_snapshot(item,old.noacl)!=cat['snapshot_sha256']:raise broker.Unavailable('canary snapshot unavailable')
 root=pathlib.Path('/var/lib/software-factory-goose/evaluator')/G/'broker';fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  runner=backend.Backend(fd,cat,helper,deadline.Deadline(base,cat),lambda e:backend.verify_snapshot(e,old.noacl));service=broker.Broker(fd,cat['snapshot_sha256'],runner,G,old.noacl);server.validate_listener(3,old.noacl);listener=socket.fromfd(3,socket.AF_UNIX,socket.SOCK_STREAM)
  try:
   while True:
    conn,_=listener.accept()
    with conn:server.handle(conn,service)
  finally:listener.close()
 finally:os.close(fd)
if __name__=='__main__':
 try:main()
 except Exception:
  print('synthetic evaluator unavailable',file=sys.stderr);raise SystemExit(1)
