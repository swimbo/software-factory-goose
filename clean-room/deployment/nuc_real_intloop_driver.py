"""Single-use fixed real INT-LOOP driver; no promotion or automatic retries.

Every ambiguous stage retains root-owned intents and quarantines the generation.
Container removal and recovery are deliberately delegated to the separately
reviewed exact-ID cleanup protocol. Never print token, credential or model text.
"""
import hashlib,http.client,json,os,pathlib,re,socket,stat,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_real_preclaim_readiness as ready
G='01M65NEH5T767H8Q5X71TTFR5S';TASK='01M65NEH5TBPKNDW21TE6FR3XA';INTENT='01M65NEH5T1Z0JWW2YCV44DY01';PULL='01M65NEH5T5TM6JH5KN5KNKDXE'
ROOT=old.ETC;STATE=pathlib.Path('/var/lib/software-factory-goose/stop');RELAY=pathlib.Path('/var/lib/software-factory-goose/relay')/G;HANDOFF=pathlib.Path('/var/lib/software-factory-goose/handoff')/G
CONFIG_SHA='1fe972454f55de3f6dd9e3f7783e810470e628a7f9da304a740412062a9dc1bf'
BINARIES={'root-grant-prepare':'4905a5bfda3ca5f62ba6ffc9e997961a64e2066baafee7b7bd28ccb4b2052af7','root-launch':'2c6dad55387e3e2e33e12f8ea8677e2e8987925fe189a2c17dcb61d577691157','sfactory_deadline_kernel_stop':'e286a8daab464f29e14e11beed0147cf24a11b585b4dfc50e48cb8615d0a325a'}
START=ROOT/(G+'.intloop-driver-started.json');DONE=ROOT/(G+'.intloop-driver-complete.json')
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','SYSTEMD_IN_CHROOT':'0'}

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE),'driver already attempted')
 cfg=json.loads(old.read(ROOT/'real-runtime.json',0o644,CONFIG_SHA));require(cfg['task_id']==TASK and cfg['intent_id']==INTENT and cfg['launch_scope']['generation']==G,'runtime catalog changed')
 for name,sha in BINARIES.items():old.read(old.PREFIX/name,0o755,sha,100_000_000)
 for stage in ('submit','pull','grant','launch','stop'):
  name='sfactory-intloop-'+stage+'-'+G.lower()+'.service'
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','stage unit occupied')
 readiness=ready.make_plan(ready.Host('fixed-driver-preflight'))
 return {'generation':G,'task':TASK,'intent':INTENT,'pull':PULL,'ttl_ms':300000,'config_sha256':CONFIG_SHA,'binaries':BINARIES,'readiness':readiness,'scope':'one authorized live generation; no promotion; retain unknown outcomes'}

def record(stage,value):old.store(STATE/(G+'.intloop-'+stage+'.json'),json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)

def error_categories(stderr):
 text=stderr.decode('utf8','replace').lower()
 allowed=('permission denied','operation not permitted','catalog','scope','binding','deadline','helper','socket','cgroup','timeout','launch','systemd')
 return [category for category in allowed if category in text]

def systemd(stage,user,argv,timeout,limit=65536):
 name='sfactory-intloop-'+stage+'-'+G.lower()+'.service'
 args=['/usr/bin/systemd-run','--unit='+name,'--wait','--pipe','--quiet','--property=User='+user,'--property=Group='+user,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=MemoryMax=256M','--property=TasksMax=32','--property=CPUQuota=100%','--property=RuntimeMaxSec='+str(timeout-10)+'s',*argv]
 p=subprocess.run(args,env=ENV,capture_output=True,timeout=timeout,check=False)
 if len(p.stdout)>limit or len(p.stderr)>8192 or p.returncode!=0:
  record(stage+'-failure',{'stage':stage,'exit_status':p.returncode,'output_bound_exceeded':len(p.stdout)>limit or len(p.stderr)>8192,'categories':error_categories(p.stderr[:8192])})
  raise RuntimeError(stage+' outcome unknown')
 return p.stdout

CLIENT=r'''import hashlib,http.client,json,os,socket,sys
kind=sys.argv[1];value=json.loads(sys.argv[2]);expected_uid=1000 if kind=='submit' else 2001
if os.geteuid()!=expected_uid:raise RuntimeError('peer identity mismatch')
path='/run/software-factory-goose/real-'+('intake' if kind=='submit' else 'worker')+'.sock'
class Conn(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(12);self.sock.connect(path)
c=Conn('localhost',timeout=12);data=json.dumps(value,separators=(',',':')).encode();c.request('POST','/'+kind,data,{'Content-Type':'application/json','Connection':'close'});r=c.getresponse();raw=r.read(65537)
if r.status!=200 or len(raw)>65536:raise RuntimeError('journal outcome unknown')
obj=json.loads(raw)
if kind=='submit':
 if obj.get('intent_id')!='01M65NEH5T1Z0JWW2YCV44DY01':raise RuntimeError('wrong intake')
 print(json.dumps({'intent_id':obj['intent_id']}))
else:
 a=obj['Assigned'];lease=a['lease']
 if a['work_package_id']!='01M65NEH5TBPKNDW21TE6FR3XA' or a['spec']!={'repository':'hello-int-loop-20261030','base_revision':'8462f440665066b35fffa0c0e42686065758f2e6'} or lease['worker_id']!='hello-int-loop-worker' or lease['attempt']!=1:raise RuntimeError('wrong claim')
 print(json.dumps({'task_id':a['work_package_id'],'attempt':lease['attempt'],'token_sha256':hashlib.sha256(lease['token'].encode()).hexdigest(),'expires_at_ms':lease['expires_at_ms'],'hard_deadline_ms':lease['hard_deadline_ms']}))
'''
def client(stage,user,payload):
 output=systemd(stage,user,['/usr/bin/python3','-I','-B','-c',CLIENT,stage,json.dumps(payload,separators=(',',':'))],35)
 return json.loads(output)
def native(stage,binary,timeout):
 return systemd(stage,'root',[str(old.PREFIX/binary),G],timeout)

def observe(goose_id):
 require(re.fullmatch(r'[0-9a-f]{64}',goose_id) is not None,'invalid Goose ID')
 deadline=time.monotonic()+165
 while time.monotonic()<deadline:
  p=subprocess.run(['/usr/bin/docker','--host','unix:///run/docker.sock','--config',str(old.RUN/'docker-empty-config'),'inspect',goose_id],env=ENV,capture_output=True,timeout=8,check=False)
  require(p.returncode==0 and len(p.stdout)<=1048576 and len(p.stderr)<=8192,'Goose observation unknown')
  objects=json.loads(p.stdout);require(len(objects)==1,'Goose identity unavailable');obj=objects[0];config=obj['Config'];state=obj['State']
  require(obj['Id']==goose_id and (config.get('Labels') or {}).get('org.software-factory.generation')==G and (config.get('Labels') or {}).get('org.software-factory.role')=='goose','Goose identity mismatch')
  if state['Status']=='exited':
   require(type(state['ExitCode']) is int and state['ExitCode']==0,'Goose did not finish successfully')
   return {'id':goose_id,'exit_code':0}
  require(state['Status']=='running','Goose outcome unknown');time.sleep(1)
 raise RuntimeError('Goose deadline exceeded')

def stop_generation():
 record('stop-started',{'generation':G})
 # Root native stop closes/freeze/kills the fixed cgroup; Docker state remains for reconciliation.
 native('stop','sfactory_deadline_kernel_stop',40)
 cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+G.lower()+'.slice');s=os.stat(cg);require((s.st_dev,s.st_ino)==(29,7663196) and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'kernel stop unresolved')
 record('stop-complete',{'generation':G,'cgroup_dev':s.st_dev,'cgroup_ino':s.st_ino,'empty':True,'engine_reconciled':False})

def read_owned(path,uid,mode,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==uid and st.st_gid==uid and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==mode and 0<st.st_size<=limit,'owned result unavailable')
  old.noacl(fd);data=bytearray()
  while len(data)<=limit:
   chunk=os.read(fd,min(65536,limit+1-len(data)))
   if not chunk:break
   data.extend(chunk)
  require(len(data)==st.st_size,'owned result changed');return bytes(data)
 finally:os.close(fd)

def inspect_outputs(binding):
 done=json.loads(read_owned(RELAY/(G+'.done.json'),2000,0o600,16384));require(done.get('schema')==1 and done.get('generation')==G and done.get('binding_sha256')==binding and done.get('phase')=='done' and isinstance(done.get('observations'),list) and len(done['observations'])==2,'relay completion unavailable')
 writer=json.loads(read_owned(HANDOFF/'output'/'result.json',2001,0o644,2048));require(set(writer)=={'status','digests'} and writer['status']=='executed' and set(writer['digests'])=={'hello.py','test_hello.py'},'writer result unavailable')
 candidate=HANDOFF/'candidate';require(set(os.listdir(candidate))=={'hello.py','test_hello.py'},'candidate file set mismatch')
 hashes={name:hashlib.sha256(read_owned(candidate/name,2001,0o644,8192)).hexdigest() for name in ('hello.py','test_hello.py')}
 require(hashes==writer['digests'],'candidate digest mismatch')
 return {'relay_done':True,'candidate_sha256':hashes,'provider_observations':done['observations']}

def apply(approved):
 require(plan()==approved,'driver plan changed');old.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 cfg=json.loads(old.read(ROOT/'real-runtime.json',0o644,CONFIG_SHA));outcome=None;failure=None
 try:
  record('submit-started',{'intent':INTENT});submitted=client('submit','bo',{'key':INTENT,'request':cfg['request']});require(submitted=={'intent_id':INTENT},'submit response mismatch');record('submit-complete',submitted)
  record('pull-started',{'pull':PULL});claim=client('pull','sfgoose-worker',{'request_id':PULL,'ttl_ms':300000});require(claim.get('task_id')==TASK and claim.get('attempt')==1 and re.fullmatch(r'[0-9a-f]{64}',claim.get('token_sha256','')),'claim mismatch');record('pull-complete',claim)
  record('grant-started',{'generation':G,'token_sha256':claim['token_sha256']});grant=json.loads(native('grant','root-grant-prepare',60));require(set(grant)=={'generation','binding_sha256','expires_at_ms','engine_effects'} and grant['generation']==G and grant['engine_effects'] is False and re.fullmatch(r'[0-9a-f]{64}',grant['binding_sha256']) and grant['expires_at_ms']==claim['expires_at_ms'],'grant mismatch');record('grant-complete',grant)
  record('launch-started',{'generation':G,'binding_sha256':grant['binding_sha256']});launch=json.loads(native('launch','root-launch',190));require(set(launch)=={'generation','id'} and launch['generation']==G and re.fullmatch(r'[0-9a-f]{64}',launch['id']),'launch response unknown');record('launch-complete',launch)
  outcome=observe(launch['id']);record('goose-exited',outcome)
 except Exception as exc:
  failure=exc
 try:stop_generation()
 except Exception as stop_error:raise RuntimeError('kernel stop unknown; retain all state and exact IDs') from stop_error
 if failure is not None:raise RuntimeError('generation outcome unknown or failed; kernel closed, reconciliation required') from failure
 # No candidate is evaluated or accepted here; exact container cleanup is a separate root protocol.
 outputs=inspect_outputs(grant['binding_sha256']);record('outputs-observed',outputs)
 result={'generation':G,'goose_exit':outcome['exit_code'],'kernel_empty':True,'engine_reconciled':False,'cleanup_required':True,'promotion':False,**outputs}
 old.store(DONE,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return result
