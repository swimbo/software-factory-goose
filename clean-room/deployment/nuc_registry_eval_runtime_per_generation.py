#!/usr/bin/python3
"""Fixed socket-activated evaluator broker candidate; not installed or enabled."""
import hashlib,json,os,pathlib,socket,stat,sys
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/relay')
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/evaluator-production')
import nuc_grant_sidecar_install as old
import nuc_registry_eval_backend_v3 as backend
import nuc_registry_eval_bootstrap_per_generation as bootstrap
import nuc_registry_eval_broker as broker
import nuc_registry_eval_deadline as deadline
import nuc_registry_eval_server_per_generation as server
import nuc_registry_eval_snapshot_provision as provision
import nuc_registry_transition_gate as gate
COORD_SHA='5c236c7ccf77b93d3c9ac89f05e9fc464afc8361e13e0aff26eafeb0fd4d1360'
HELPER_SHA='604da40498617a9abd5b190b27012abcf56644c025bf71b03cb951e2641bb90e'
PACKAGE_SHA='4cb5a74f7a8027c03edb217b3a5e83ac0af968749cbba6124480c760db8380af'
class GuardedBroker:
 def __init__(self,inner,generation):self.inner=inner;self.generation=generation
 def run(self,uid,request):
  # Hold the shared registry gate for the complete challenge lifecycle.
  with gate.admission():
   generation,_,_=provision.selected()
   if generation!=self.generation:raise broker.Unavailable('generation unavailable')
   return self.inner.run(uid,request)
def handle_connection(conn,service,generation):
 server.handle(conn,GuardedBroker(service,generation))
def verify_package():
 manifest=json.loads(old.read(old.ETC/'evaluator-package.json',0o600));pins=manifest.get('files')
 required={'nuc_grant_sidecar_install.py','nuc_registry_eval_runtime_per_generation.py','nuc_registry_eval_bootstrap_per_generation.py','nuc_registry_eval_backend_v3.py','nuc_registry_eval_broker.py','nuc_registry_eval_deadline.py','nuc_registry_eval_server_per_generation.py','nuc_registry_eval_client_per_generation.py','nuc_registry_eval_coordinator_per_generation.py','nuc_registry_evaluator.py','nuc_registry_eval_snapshot_provision.py','nuc_registry_eval_provenance.py','nuc_registry_transition_gate.py','nuc_registry_attestation_profiles.py'}
 if manifest.get('schema')!=1 or not isinstance(pins,dict) or set(pins)!=required:raise broker.Unavailable('package unavailable')
 directory=os.open('/usr/local/libexec/software-factory-goose/evaluator-production',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for name,digest in pins.items():
   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
   try:
    st=os.fstat(fd);old.noacl(fd)
    if not stat.S_ISREG(st.st_mode) or (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))!=(0,2002,1,0o440) or st.st_size>1000000:raise broker.Unavailable('package unavailable')
    raw=os.read(fd,1000001)
    if len(raw)!=st.st_size or hashlib.sha256(raw).hexdigest()!=digest:raise broker.Unavailable('package changed')
   finally:os.close(fd)
 finally:os.close(directory)
def main():
 if os.getuid()!=0 or os.geteuid()!=0 or len(sys.argv)!=1:raise broker.Unavailable('runtime unavailable')
 fields=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
 if fields.get('NoNewPrivs','').strip()!='1' or any(int(fields[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise broker.Unavailable('runtime unavailable')
 verify_package()
 old.read(old.ETC/'relay-package.json',0o600,PACKAGE_SHA)
 raw=old.read(old.PREFIX/'root-launch-host.py',0o755,HELPER_SHA,1_000_000);helper={'__name__':'fixed_evaluator_helper'};exec(compile(raw,'<pinned-helper>','exec'),helper);base,_=helper['modules']()
 cat=bootstrap.active_catalog(COORD_SHA);path=pathlib.Path('/var/lib/software-factory-goose/evaluator')/cat['generation']/'broker'
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  native=deadline.Deadline(base,cat);runner=backend.Backend(fd,cat,helper,native,lambda e:backend.verify_snapshot(e,old.noacl));service=broker.Broker(fd,cat['snapshot_sha256'],runner,cat['generation'],old.noacl)
  server.validate_listener(3,old.noacl,cat['generation']);listener=socket.fromfd(3,socket.AF_UNIX,socket.SOCK_STREAM)
  try:
   while True:
    conn,_=listener.accept()
    with conn:handle_connection(conn,service,cat['generation'])
  finally:listener.close()
 finally:os.close(fd)
if __name__=='__main__':
 try:main()
 except Exception:
  print('evaluator broker unavailable',file=sys.stderr);raise SystemExit(1)
