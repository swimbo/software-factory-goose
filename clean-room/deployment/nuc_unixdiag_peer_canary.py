"""One bounded PID1 UID2000 synthetic Unix peer diagnostic; no live sockets."""
import hashlib,json,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
SOURCE=None;SOURCE_SHA='1e368e3f4e3d88cc587eb97451246defa91cc6b21625fcf871d43ce73620f0c6'
UNIT='sfactory-unixdiag-peer-canary.service';START=old.ETC/'unixdiag-peer-canary-started.json';DONE=old.ETC/'unixdiag-peer-canary-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'
def plan():
 require(os.geteuid()==0 and isinstance(SOURCE,bytes) and 0<len(SOURCE)<=65536 and hashlib.sha256(SOURCE).hexdigest()==SOURCE_SHA and not any(os.path.lexists(x) for x in (START,DONE)),'fixture unavailable')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied');paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for root in map(pathlib.Path,paths):
  for name in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/name),'unit collision')
 return {'schema':1,'source_sha256':SOURCE_SHA,'unit':UNIT,'scope':'synthetic inherited connected Unix FD, private namespace/tmp, UID2000; no live service access'}
def apply(reviewed):
 require(plan()==reviewed,'fixture plan changed');old.store(START,canonical(reviewed),0o600)
 argv=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=PrivateTmp=yes','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=8','--property=RuntimeMaxSec=15s','/usr/bin/python3','-I','-B','-c',SOURCE.decode()]
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=25,check=False);require(p.returncode==0 and len(p.stdout)<=1024 and len(p.stderr)<=4096,'fixture outcome unknown');out=json.loads(p.stdout)
 require(out=={'schema':1,'synthetic_inherited_connected_fd_detected':True,'bidirectional_peer_match':True,'raw_inodes_exposed':False} and old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','fixture result unavailable')
 old.store(DONE,canonical(out),0o600);return out
