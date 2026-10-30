"""One-shot no-engine qualified intake, claim and root grant on retained journal."""
import hashlib,json,os,pathlib,socket,subprocess
import nuc_grant_sidecar_resume as resume
import nuc_grant_sidecar_install as install

ROOT=install.ETC
START=ROOT/'grant-journal-canary-started.json'; DONE=ROOT/'grant-journal-canary-complete.json'
PULL='01M65GTQYKXECJWHCPKQD248SZ'
REQUEST={'schema_version':1,'repository':'fixture','target_ref':'refs/heads/main','base_revision':'a'*40,'intent':'build fixture','acceptance_criteria':['passes fixture']}
SCOPE={'task_id':install.TASK,'intent_id':install.INTAKE,'queue_id':install.QUEUE,'generation':install.GEN,'spec':{'repository':'fixture','base_revision':'a'*40},'worker_id':install.WORKER,'catalog_sha256':install.CATALOG_SHA}

def store(name,obj):install.store(ROOT/name,json.dumps(obj,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
def readjson(path,mode):return json.loads(install.read(path,mode))
def plan():
 resume.require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE),'canary already attempted')
 complete=readjson(resume.DONE,0o600);resume.require(complete['registration']=={'deployment_id':resume.DID,'invocation_id':resume.INVOCATION,'service_count':4} and complete['production_accepted'] is False and complete['engine_enabled'] is False,'resume receipt mismatch')
 install.read(resume.MARKER,0o644,hashlib.sha256(b'private canary bootstrap completed; acceptance tests required\n').hexdigest())
 install.read(ROOT/'grant-runtime.json',0o644,resume.CONFIG_SHA)
 running=install.sidecar_running();resume.require(running==complete['sidecar'],'sidecar identity changed')
 old=install.old_snapshot();resume.old_inspect();resume.new_intake_empty()
 return {'old':old,'sidecar':running,'scope':SCOPE,'pull':PULL,'no_engine':True}

CLIENT=r'''import hashlib,http.client,json,socket,sys
mode=sys.argv[1]; body=json.loads(sys.argv[2]); path={'submit':'/run/software-factory-goose/grant-intake.sock','pull':'/run/software-factory-goose/grant-worker.sock'}[mode]
class Conn(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(12);self.sock.connect(path)
c=Conn('localhost',timeout=12);data=json.dumps(body,separators=(',',':')).encode();c.request('POST','/'+mode,data,{'Content-Type':'application/json','Connection':'close'});r=c.getresponse();raw=r.read(65537)
if r.status!=200 or len(raw)>65536:raise RuntimeError('operation unavailable or unknown')
obj=json.loads(raw)
if mode=='submit':
 if obj.get('intent_id')!='01M65GTQYKXECJWHCPKQD248SY':raise RuntimeError('intake scope mismatch')
 print(json.dumps({'intent_id':obj['intent_id'],'status':r.status}))
else:
 a=obj['Assigned'];lease=a['lease']
 if a['work_package_id']!='01M65GTQYKQQMN3NG1V0EFCVH5' or a['spec']!={'repository':'fixture','base_revision':'a'*40} or lease['worker_id']!='root-grant-canary-worker' or lease['attempt']!=1:raise RuntimeError('claim scope mismatch')
 print(json.dumps({'task_id':a['work_package_id'],'attempt':lease['attempt'],'token_sha256':hashlib.sha256(lease['token'].encode()).hexdigest(),'expires_at_ms':lease['expires_at_ms'],'hard_deadline_ms':lease['hard_deadline_ms']}))
'''

def client(role,mode,body):
 p=resume.role_probe(role,['/usr/bin/python3','-I','-B','-c',CLIENT,mode,json.dumps(body,separators=(',',':'))],25)
 resume.require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'client outcome unknown');return json.loads(p.stdout)

def grant():
 body=json.dumps({'generation':install.GEN},separators=(',',':')).encode();s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(15)
 try:
  s.connect(str(install.RUN/'launch-grant.sock'))
  s.sendall(b'POST /reserve HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
  import http.client
  r=http.client.HTTPResponse(s);r.begin();data=r.read(16385);resume.require(r.status==200 and len(data)<=16384,'grant outcome unknown');obj=json.loads(data)
  resume.require(obj.get('scope')==SCOPE and obj.get('generation')==install.GEN and obj.get('attempt')==1,'grant scope mismatch')
  return obj
 finally:s.close()

def apply(approved):
 resume.require(plan()==approved,'canary plan changed');store(START,approved)
 store('grant-journal-submit-started.json',{'intent':install.INTAKE})
 submitted=client('bo','submit',{'key':install.INTAKE,'request':REQUEST})
 store('grant-journal-submit-complete.json',submitted)
 store('grant-journal-pull-started.json',{'pull':PULL})
 claim=client('sfgoose-worker','pull',{'request_id':PULL,'ttl_ms':300000})
 store('grant-journal-pull-complete.json',claim)
 store('grant-journal-reserve-started.json',{'generation':install.GEN,'token_sha256':claim['token_sha256']})
 result=grant()
 resume.require(all(result[k]==claim[k] for k in ('attempt','token_sha256','expires_at_ms','hard_deadline_ms')),'grant does not bind claim')
 canonical=json.dumps(result,sort_keys=True,separators=(',',':')).encode();digest=hashlib.sha256(canonical).hexdigest()
 install.store(ROOT/'grant-journal-grant.json',canonical+b'\n',0o600)
 store('grant-journal-reserve-complete.json',{'sha256':digest,'scope':SCOPE})
 store('grant-journal-replay-started.json',{'sha256':digest})
 replay=grant();resume.require(replay==result,'grant replay changed')
 resume.require(resume.grant_status('01M65GTQYKNHFXSJSZ55D7T363')==403,'wrong generation was not denied')
 store('grant-journal-replay-complete.json',{'sha256':digest,'wrong_generation_denied':True})
 resume.require(install.old_snapshot()==approved['old'] and install.sidecar_running()==approved['sidecar'],'service identity changed')
 resume.old_inspect()
 outcome={'grant_sha256':digest,'scope':SCOPE,'claim_bound':True,'grant_replay_identical':True,'wrong_generation_denied':True,'old_intake_readable':True,'engine_started':False,'production_accepted':False}
 store(DONE.name,outcome);return outcome
