#!/usr/bin/python3
"""Synthetic-only evaluator runtime; cannot read the production catalog."""
import hashlib,json,os,pathlib,re,socket,stat,sys
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/evaluator')
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/relay')
import nuc_grant_sidecar_install as old
import nuc_registry_eval_backend as backend
import nuc_registry_eval_broker as broker
import nuc_registry_eval_deadline as deadline
import nuc_registry_eval_server as server
G='01M65RMR3F04YB1B016EBBSXGK';HELPER_SHA='604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e';PACKAGE_SHA='4cb5a74f7a8027c03edb217b3a5e83ac0af968749cbba6124480c760db8380af'
def verify_sources():
 plan=json.loads(old.read(old.ETC/'evaluator-canary-provision-started.json',0o600));pins=plan.get('source_sha256')
 if not isinstance(pins,dict) or len(pins)!=12:raise broker.Unavailable('source manifest unavailable')
 pins=dict(pins)
 for name,receipt in [('nuc_registry_eval_backend.py','evaluator-canary-backend-v2-complete.json'),('nuc_registry_eval_canary_runtime.py','evaluator-canary-runtime-v2-complete.json')]:
  value=json.loads(old.read(old.ETC/receipt,0o600))
  if value.get('generation')!=G or value.get('fixture_only') is not True or value.get('activated') is not False or value.get('previous_sha256')!=pins.get(name):raise broker.Unavailable('source upgrade unavailable')
  digest=value.get('backend_sha256') if 'backend' in name else value.get('runtime_sha256')
  if not isinstance(digest,str) or re.fullmatch(r'[0-9a-f]{64}',digest) is None:raise broker.Unavailable('source upgrade unavailable')
  pins[name]=digest
 root=os.open('/usr/local/libexec/software-factory-goose/evaluator',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for name,digest in pins.items():
   if not isinstance(name,str) or re.fullmatch(r'[A-Za-z0-9_.-]+',name) is None or name in ('.','..'):raise broker.Unavailable('source name unavailable')
   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=root)
   try:
    st=os.fstat(fd);old.noacl(fd)
    if not stat.S_ISREG(st.st_mode) or (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))!=(0,2002,1,0o440) or st.st_size>1000000:raise broker.Unavailable('source unavailable')
    raw=os.read(fd,1000001)
    if len(raw)!=st.st_size or hashlib.sha256(raw).hexdigest()!=digest:raise broker.Unavailable('source changed')
   finally:os.close(fd)
 finally:os.close(root)
def main():
 if os.getuid()!=0 or os.geteuid()!=0 or len(sys.argv)!=1:raise broker.Unavailable('canary unavailable')
 fields=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
 if fields.get('NoNewPrivs','').strip()!='1' or any(int(fields[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise broker.Unavailable('canary unavailable')
 verify_sources();old.read(old.ETC/'relay-package.json',0o600,PACKAGE_SHA);raw=old.read(old.PREFIX/'root-launch-host.py',0o755,HELPER_SHA,1_000_000);helper={'__name__':'synthetic_evaluator_helper'};exec(compile(raw,'<pinned-helper>','exec'),helper);base,_=helper['modules']()
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
