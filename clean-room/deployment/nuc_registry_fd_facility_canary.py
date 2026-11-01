"""Read-only same-UID /proc FD visibility canary against the current SDK4.

 Tests only visibility. It does not attest absence of an inherited admin client
 socket, because client socket inodes need not match a Unix listener's inode.
"""
import hashlib,os,pathlib,subprocess
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_process_attestation as process
SOURCE=None;SOURCE_SHA='47558707ab52f9683cfb9ed00cf8d95eddd7a443979d4101c11c347f955e5203'
UNIT='sfactory-registry-sdk4-fd-visibility.service'
START=old.ETC/'registry-sdk4-fd-visibility-started.json';DONE=old.ETC/'registry-sdk4-fd-visibility-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan_locked():
 require(os.geteuid()==0 and isinstance(SOURCE,bytes) and 0<len(SOURCE)<=65536 and hashlib.sha256(SOURCE).hexdigest()==SOURCE_SHA and not any(os.path.lexists(x) for x in (START,DONE)),'facility unavailable')
 head=gate.verify_head();manifest=gate._protected_read(gate.REGISTRY,0o644,65536);profile=gate.registry_profile(manifest);require(profile['profile']=='sdk4','SDK4 unavailable')
 raw=gate._protected_read(profile['attestation'],0o600,16384);att=gate._json(raw)
 probe=profile['probe'];require(hashlib.sha256(gate._protected_read(probe,0o755,10000000)).hexdigest()==profile['probe_sha256'],'attestor unavailable')
 p=subprocess.run([str(probe)],env=old.ENV,capture_output=True,timeout=50,check=False);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192 and gate._json(p.stdout)=={'service_attested':True,'grant_requested':False},'SDK4 attestation unavailable')
 unit='software-factory-goose-registry-runtime.service';current=process.properties(unit);require(current.get('ActiveState')=='active' and current.get('MainPID')==str(att['pid']) and current.get('Names')==unit and current.get('ControlGroup')=='/system.slice/'+unit and process.ticks(att['pid'])==att['start_ticks'],'SDK4 identity changed')
 inv=old.ctl('show',unit,'-p','InvocationID','--value');require(len(inv)==32,'SDK4 invocation unavailable')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','canary unit occupied');paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=UNIT.removesuffix('.service')
 for root in map(pathlib.Path,paths):
  for name in [UNIT,UNIT+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/name),'unit collision')
 return {'schema':1,'head':head,'source_sha256':SOURCE_SHA,'pid':att['pid'],'start_ticks':att['start_ticks'],'invocation_id':inv,'namespace_dev':att['netns_dev'],'namespace_ino':att['netns_ino'],'scope':'one read-only same-UID FD visibility check; no socket provenance claim'}
def plan():
 with gate.admission():return plan_locked()
def apply(reviewed):
 with gate.admission():
  require(plan_locked()==reviewed,'facility plan changed');old.store(START,__import__('json').dumps(reviewed,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
  request={k:reviewed[k] for k in ('pid','start_ticks','namespace_dev','namespace_ino')}
  args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+process.ANCHOR_UNIT,'--property=BindsTo='+process.ANCHOR_UNIT,'--property=After='+process.ANCHOR_UNIT,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=8','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',SOURCE.decode(),'facility']
  p=subprocess.run(args,input=__import__('json').dumps(request,sort_keys=True,separators=(',',':')).encode(),env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and len(p.stdout)<=1024 and len(p.stderr)<=4096,'FD visibility unavailable')
  result=gate._json(p.stdout);require(isinstance(result,dict) and set(result)=={'schema','mode','fd_count','socket_fd_count'} and result['schema']==1 and result['mode']=='facility' and type(result['fd_count']) is int and 0<result['fd_count']<=1024 and type(result['socket_fd_count']) is int and 0<=result['socket_fd_count']<=result['fd_count'],'FD result unavailable')
  require(old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='' and process.properties('software-factory-goose-registry-runtime.service').get('MainPID')==str(reviewed['pid']) and process.ticks(reviewed['pid'])==reviewed['start_ticks'] and old.ctl('show','software-factory-goose-registry-runtime.service','-p','InvocationID','--value')==reviewed['invocation_id'] and gate.verify_head()==reviewed['head'],'SDK4 changed')
  record={'schema':1,'source_sha256':SOURCE_SHA,'pid':reviewed['pid'],'invocation_id':reviewed['invocation_id'],'fd_count':result['fd_count'],'socket_fd_count':result['socket_fd_count'],'fd_visibility':True,'inherited_admin_absence_proven':False};old.store(DONE,__import__('json').dumps(record,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return record
