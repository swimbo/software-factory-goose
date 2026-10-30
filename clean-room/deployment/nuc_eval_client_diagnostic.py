"""Read-only UID2002 evaluator client diagnostic; never connects or sends."""
import hashlib,json,os,subprocess
import nuc_grant_sidecar_install as old
NAME='sfactory-eval-client-diagnostic-20261030.service';G='01M65RMR3F04YB1B016EBBSXGK';START=old.ETC/'eval-client-diagnostic-started.json';DONE=old.ETC/'eval-client-diagnostic-complete.json'
CODE=r'''import errno,json,os,sys
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/evaluator')
result={}
def stage(name,fn):
 try:fn();result[name]={'status':'pass'}
 except OSError as e:result[name]={'status':'os_error','errno':e.errno if e.errno in (1,2,9,13,20,40,95) else 'other'}
 except Exception as e:
  text=str(e);allowed={'identity unavailable','attestation unavailable','attestation directory unavailable','ACL unavailable','boot changed','unit changed','socket parent unavailable','socket ancestor unavailable','socket changed','socket ACL unavailable','manager unavailable','broker changed'}
  result[name]={'status':'denied','category':text if text in allowed else 'other'}
def imports():
 global c
 import nuc_registry_eval_client as c
 c.UNIT_NAME='software-factory-goose-eval-canary.service';c.UNIT=__import__('pathlib').Path('/etc/systemd/system')/c.UNIT_NAME
stage('imports',imports)
if 'c' in globals():stage('verify',lambda:c.verify('01M65RMR3F04YB1B016EBBSXGK'))
print(json.dumps({'checks':result,'connected':False,'challenge_requested':False},sort_keys=True))
'''
def plan():
 if os.geteuid()!=0 or any(os.path.lexists(p) for p in (START,DONE)) or old.ctl('show',NAME,'-p','LoadState','--value')!='not-found':raise RuntimeError('diagnostic occupied')
 return {'unit':NAME,'program_sha256':hashlib.sha256(CODE.encode()).hexdigest(),'scope':'read-only UID2002 client verification; no socket connection'}
def apply(approved):
 if plan()!=approved:raise RuntimeError('plan changed')
 old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 args=['/usr/bin/systemd-run','--unit='+NAME,'--wait','--pipe','--quiet','--property=User=sfgoose-eval','--property=Group=sfgoose-eval','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=PrivateNetwork=yes','--property=RestrictAddressFamilies=AF_UNIX','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=30s','/usr/bin/python3','-I','-B','-c',CODE]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=40,check=False)
 if p.returncode!=0 or len(p.stdout)>8192 or len(p.stderr)>8192:raise RuntimeError('diagnostic unavailable')
 value=json.loads(p.stdout)
 if value.get('connected') is not False or value.get('challenge_requested') is not False:raise RuntimeError('diagnostic scope mismatch')
 old.store(DONE,json.dumps(value,sort_keys=True).encode()+b'\n',0o600);return value
