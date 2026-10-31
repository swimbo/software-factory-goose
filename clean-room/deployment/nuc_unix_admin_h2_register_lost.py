"""One fixed new SDK POST with discarded reply; success remains unknown."""
import json,os,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_registration as registration
import nuc_unix_admin_h2_helpers_install as helpers
UNIT='sfactory-unix-admin-h2-canary-register-new.service'
UNKNOWN=old.ETC/'unix-admin-h2-canary-register-new-unknown.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 registration.ROLE='new';p=registration.plan();require(not os.path.lexists(UNKNOWN),'registration already observed');receipt=json.loads(old.read(helpers.DONE,0o600));require(receipt=={'installed':True,'queried':False},'helper install unavailable');old.read(helpers.LOST,0o755,helpers.LOST_SHA)
 return {'schema':1,'registration':p,'lost_helper_sha256':helpers.LOST_SHA,'scope':'one fixed synthetic POST, deliberately discard response; remain unknown'}
def apply(approved):
 require(plan()==approved,'plan changed');registration.ROLE='new';started,_=registration.records('new');old.store(started,base.canonical(approved)+b'\n',0o600)
 argv=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-journal','--property=Group=sfgoose-journal','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+base.NET,'--property=BindsTo='+base.NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=30s','/usr/bin/python3','-I','-B',str(helpers.LOST)]
 p=subprocess.run(argv,env=old.ENV,capture_output=True,timeout=40,check=False);require(p.returncode==0 and p.stdout==b'DISPATCHED_RESPONSE_UNKNOWN\n' and len(p.stderr)<=4096,'dispatch outcome unknown')
 require(old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','dispatch process unresolved')
 result={'schema':1,'stage':'response_unknown','one_dispatch':True,'no_retry':True};old.store(UNKNOWN,base.canonical(result)+b'\n',0o600);return result
