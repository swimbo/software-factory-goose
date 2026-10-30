#!/usr/bin/python3
"""Fixed socket-activated evaluator broker candidate; not installed or enabled."""
import os,pathlib,socket,sys
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/evaluator')
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/relay')
import nuc_grant_sidecar_install as old
import nuc_registry_eval_backend as backend
import nuc_registry_eval_bootstrap as bootstrap
import nuc_registry_eval_broker as broker
import nuc_registry_eval_deadline as deadline
import nuc_registry_eval_server as server
COORD_SHA='5c236c7ccf77b93d3c9ac89f05e9fc464afc8361e13e0aff26eafeb0fd4d1360'
HELPER_SHA='604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e'
PACKAGE_SHA='4cb5a74f7a8027c03edb217b3a5e83ac0af968749cbba6124480c760db8380af'
def main():
 if os.getuid()!=0 or os.geteuid()!=0 or len(sys.argv)!=1:raise broker.Unavailable('runtime unavailable')
 fields=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
 if fields.get('NoNewPrivs','').strip()!='1' or any(int(fields[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise broker.Unavailable('runtime unavailable')
 old.read(old.ETC/'relay-package.json',0o600,PACKAGE_SHA)
 raw=old.read(old.PREFIX/'root-launch-host.py',0o755,HELPER_SHA,1_000_000);helper={'__name__':'fixed_evaluator_helper'};exec(compile(raw,'<pinned-helper>','exec'),helper);base,_=helper['modules']()
 cat=bootstrap.catalog(COORD_SHA);path=pathlib.Path('/var/lib/software-factory-goose/evaluator')/cat['generation']/'broker'
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  native=deadline.Deadline(base,cat);runner=backend.Backend(fd,cat,helper,native,lambda e:backend.verify_snapshot(e,old.noacl));service=broker.Broker(fd,cat['snapshot_sha256'],runner,cat['generation'],old.noacl)
  server.validate_listener(3,old.noacl);listener=socket.fromfd(3,socket.AF_UNIX,socket.SOCK_STREAM)
  try:
   while True:
    conn,_=listener.accept()
    with conn:server.handle(conn,service)
  finally:listener.close()
 finally:os.close(fd)
if __name__=='__main__':
 try:main()
 except Exception:
  print('evaluator broker unavailable',file=sys.stderr);raise SystemExit(1)
