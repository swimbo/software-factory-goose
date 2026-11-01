"""Bounded fresh PID1 observers for the v5 admission producer.

 Caller holds the registry admission lock and brackets calls with live head,
 process, socket and fence checks. No observer can authorize an admission.
"""
import hashlib,json,os,pathlib,re,subprocess,uuid
import nuc_grant_sidecar_install as old
import nuc_registry_transition_gate as gate
import nuc_registry_process_attestation as anchor
JOURNAL=old.PREFIX/'registry-admission-journal-probe.py'
JOURNAL_SHA='0384219143ae6ae757b43c58ece9d85b2ac0ca0d784cda2e19a339ad8a1e4723'
DENY=old.PREFIX/'registry-admin-deny-probe.py'
DENY_SHA='001442ef01ea29bab184df41280cafda496bf9748aaf8dab5babc579b6a6a373'

def require(v,m):
 if not v:raise RuntimeError(m)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'
def unit_available(unit):
 require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','observer unit occupied')
 roots=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(roots,'unit search unavailable');stem=unit.removesuffix('.service')
 for root in map(pathlib.Path,roots):
  for candidate in [unit,unit+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(root/candidate),'observer unit collision')
def run(role,namespace,deployment=None):
 require(role in ('journal','deny') and isinstance(namespace,list) and len(namespace)==2 and all(type(v) is int and v>0 for v in namespace),'observer scope unavailable')
 path,pin,user=(JOURNAL,JOURNAL_SHA,'sfgoose-journal') if role=='journal' else (DENY,DENY_SHA,'sfgoose-control')
 old.read(path,0o755,pin,65536);unit='sfactory-v5-admission-'+role+'-'+uuid.uuid4().hex+'.service';unit_available(unit)
 request={'namespace_dev':namespace[0],'namespace_ino':namespace[1]}
 if role=='journal':
  require(isinstance(deployment,str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',deployment),'SDK5 deployment unavailable');request.update(schema=1,sdk5_deployment_id=deployment)
 argv=['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--quiet','--collect','--property=User='+user,'--property=Group='+user,'--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+anchor.ANCHOR_UNIT,'--property=BindsTo='+anchor.ANCHOR_UNIT,'--property=After='+anchor.ANCHOR_UNIT,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B',str(path)]
 p=subprocess.run(argv,input=canonical(request),env=old.ENV,capture_output=True,timeout=30,check=False);require(p.returncode==0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'observer outcome unknown');result=gate._json(p.stdout)
 if role=='deny':require(result=={'schema':1,'admin_access_denied':True},'admin denial unavailable')
 else:
  require(isinstance(result,dict) and set(result)=={'schema','admin_dev','admin_ino','old_listeners_and_established_absent','tcp_admin_absent','counts'} and result['schema']==1 and all(type(result[k]) is int and result[k]>0 for k in ('admin_dev','admin_ino')) and result['old_listeners_and_established_absent'] is True and result['tcp_admin_absent'] is True and isinstance(result['counts'],dict) and set(result['counts'])=={'invocations','queue_entries','queues'} and all(type(v) is int and v==0 for v in result['counts'].values()),'journal observation unavailable')
 return result
