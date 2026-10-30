"""Fixed post-expiry mutation denial against the retained no-engine grant."""
import hashlib,json,os,pathlib,subprocess,time
import nuc_grant_sidecar_install as install
import nuc_grant_sidecar_resume as resume
START=install.ETC/'grant-expiry-canary-started.json'; DONE=install.ETC/'grant-expiry-canary-complete.json'
NAME='sfactory-grant-expiry-canary.service'
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C'}
CODE=r'''import http.client,json,os
if os.geteuid()!=2000:raise RuntimeError('wrong identity')
config=json.load(open('/etc/software-factory-goose/runtime.json'));ns=os.stat('/proc/self/ns/net')
if (ns.st_dev,ns.st_ino)!=(config['namespace_dev'],config['namespace_ino']):raise RuntimeError('wrong namespace')
c=http.client.HTTPConnection('127.0.0.1',config['restate_ingress_port'],timeout=10)
body=json.dumps({'repository':'fixture','base_revision':'a'*40},separators=(',',':')).encode()
c.request('POST','/restate/call/ClaimLeaseJournal/01M65GTQYKQQMN3NG1V0EFCVH5/initialize',body,{'Content-Type':'application/json','Connection':'close'})
r=c.getresponse();b=r.read(16385)
if len(b)>16384:raise RuntimeError('response limit')
print(json.dumps({'status':r.status}))
c.close()
'''
def plan():
 resume.require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE),'expiry canary already attempted')
 claim=json.loads(install.read(install.ETC/'grant-journal-pull-complete.json',0o600))
 grant=json.loads(install.read(install.ETC/'grant-journal-grant.json',0o600))
 done=json.loads(install.read(install.ETC/'grant-journal-canary-complete.json',0o600))
 resume.require(grant['scope']==done['scope'] and grant['token_sha256']==claim['token_sha256'] and grant['expires_at_ms']==claim['expires_at_ms'] and time.time_ns()//1_000_000>grant['expires_at_ms'],'not past exact recorded lease expiry')
 actual=hashlib.sha256(json.dumps(grant,sort_keys=True,separators=(',',':')).encode()).hexdigest();resume.require(actual==done['grant_sha256'],'grant digest mismatch')
 p=subprocess.run(['/usr/bin/systemctl','show',NAME,'-p','LoadState','--value'],env=ENV,capture_output=True,timeout=10,check=True)
 resume.require(p.stdout.strip()==b'not-found','expiry probe name occupied')
 return {'grant_sha256':actual,'expires_at_ms':grant['expires_at_ms'],'old':install.old_snapshot(),'sidecar':install.sidecar_running(),'operation':'exact existing-spec initialize; expected reservation denial'}
def apply(approved):
 resume.require(plan()==approved,'expiry plan changed')
 install.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 args=['/usr/bin/systemd-run','--unit='+NAME,'--collect','--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf=software-factory-goose-private-net.service','--property=BindsTo=software-factory-goose-private-net.service','--property=After=software-factory-goose-private-net.service','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=MemoryMax=128M','--property=TasksMax=32','--property=CPUQuota=50%','--property=RuntimeMaxSec=15s','/usr/bin/python3','-I','-B','-c',CODE]
 p=subprocess.run(args,env=ENV,capture_output=True,timeout=25,check=False)
 resume.require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'expiry probe outcome unknown')
 obj=json.loads(p.stdout);resume.require(obj=={'status':409},'post-expiry reservation denial not proven')
 resume.require(install.old_snapshot()==approved['old'] and install.sidecar_running()==approved['sidecar'],'service identity changed')
 result={'grant_sha256':approved['grant_sha256'],'post_expiry_initialize_denied':True,'status':409,'engine_started':False}
 install.store(DONE,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return result
