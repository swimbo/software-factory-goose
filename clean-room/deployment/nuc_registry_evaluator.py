"""Host-only holdout coordinator; requires an authenticated, reconciling broker.

This candidate does not itself launch or execute candidate code. Its caller must
supply a root-authenticated broker whose run method verifies and tears down a
fresh confined process before returning; an absent/unknown result fails closed.
"""
import re

GENERATION='01M65RMR3F04YB1B016EBBSXGG'
FILES=('hello.py','test_hello.py')
MAX_OUTPUT=65536
HEX=re.compile(r'[0-9a-f]{64}\Z')
CASES=(((),b'hello world\n'),(('Ada',),b'hello Ada\n'),(('Zoë Smith',),'hello Zoë Smith\n'.encode()),(('--uppercase','Ada'),b'HELLO ADA\n'),(('Ada','--uppercase'),b'HELLO ADA\n'),(('a','b'),None),(('--bogus',),None))

class EvaluationUnavailable(RuntimeError):pass

def evaluate(snapshot,broker,generation):
 if not isinstance(generation,str) or re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',generation) is None:raise EvaluationUnavailable('generation unavailable')
 if not isinstance(snapshot,dict) or set(snapshot)!=set(FILES) or any(not isinstance(snapshot[n],str) or HEX.fullmatch(snapshot[n]) is None for n in FILES):raise EvaluationUnavailable('snapshot unavailable')
 if not callable(getattr(broker,'run',None)):raise EvaluationUnavailable('broker unavailable')
 votes=[];sequence=0
 def run(kind,args):
  nonlocal sequence
  sequence+=1
  request={'schema':1,'generation':generation,'sequence':sequence,'kind':kind,'args':list(args),'candidate_sha256':snapshot.copy()}
  try:reply=broker.run(request)
  except Exception:raise EvaluationUnavailable('challenge outcome unknown') from None
  if not isinstance(reply,dict) or set(reply)!={'schema','generation','sequence','candidate_sha256','exit_code','stdout','stderr','exact_cleanup'} or reply['schema']!=1 or reply['generation']!=generation or type(reply['sequence']) is not int or reply['sequence']!=sequence or reply['candidate_sha256']!=snapshot or reply['exact_cleanup'] is not True or type(reply['exit_code']) is not int or not isinstance(reply['stdout'],bytes) or not isinstance(reply['stderr'],bytes) or len(reply['stdout'])>MAX_OUTPUT or len(reply['stderr'])>MAX_OUTPUT:raise EvaluationUnavailable('challenge outcome unknown')
  return reply
 for args,expected in CASES:
  passed=0
  for _ in range(3):
   r=run('hello',args)
   if expected is None:passed+=int(r['exit_code']==2 and not r['stdout'] and bool(r['stderr'].strip()))
   else:passed+=int(r['exit_code']==0 and r['stdout']==expected and not r['stderr'])
  if passed<2:raise EvaluationUnavailable('holdout failed')
  votes.append(passed)
 if sum(votes)*10<len(votes)*3*9:raise EvaluationUnavailable('holdout failed')
 tests=run('unittest',())
 count=re.search(rb'Ran ([0-9]+) tests?',tests['stderr'])
 if tests['exit_code']!=0 or count is None or int(count[1])<1:raise EvaluationUnavailable('candidate tests failed or empty')
 return {'schema':1,'generation':generation,'candidate_sha256':snapshot.copy(),'scenario_votes':votes,'repetitions':3,'candidate_tests':'pass','challenges':sequence}

class UnixBroker:
 """Single-use request transport; protected listener provenance remains caller-owned."""
 def __init__(self,connect,verify):
  if not callable(connect) or not callable(verify):raise EvaluationUnavailable('broker unavailable')
  self.connect=connect;self.verify=verify;self.last=0;self.poisoned=False
 def run(self,request):
  import base64,socket,struct,time
  if self.poisoned or request.get('sequence')!=self.last+1:raise EvaluationUnavailable('sequence unavailable')
  self.last=request['sequence'] # An ambiguous write must never be replayed.
  try:
   identity=self.verify()
   conn=self.connect()
   with conn:
    pid,uid,gid=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    if uid!=0 or pid<=0:raise EvaluationUnavailable('broker peer unavailable')
    deadline=time.monotonic()+190
    conn.settimeout(190)
    raw=__import__('json').dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()+b'\n'
    if len(raw)>4096:raise EvaluationUnavailable('request unavailable')
    conn.sendall(raw);buf=bytearray()
    while b'\n' not in buf:
     remaining=deadline-time.monotonic()
     if remaining<=0:raise EvaluationUnavailable('challenge outcome unknown')
     conn.settimeout(remaining)
     chunk=conn.recv(min(4096,180001-len(buf)))
     if not chunk:raise EvaluationUnavailable('challenge outcome unknown')
     buf.extend(chunk)
     if len(buf)>180000:raise EvaluationUnavailable('challenge outcome unknown')
    if not buf.endswith(b'\n') or buf.count(b'\n')!=1:raise EvaluationUnavailable('challenge outcome unknown')
    def unique(pairs):
     out={}
     for key,value in pairs:
      if key in out:raise ValueError('duplicate')
      out[key]=value
     return out
    reply=__import__('json').loads(buf,object_pairs_hook=unique)
    for name in ('stdout','stderr'):
     value=reply[name]
     if not isinstance(value,str):raise ValueError('invalid output')
     reply[name]=base64.b64decode(value,validate=True)
    if self.verify()!=identity:raise EvaluationUnavailable('broker changed')
    return reply
  except Exception:self.poisoned=True;raise EvaluationUnavailable('challenge outcome unknown') from None
