"""Read-only exact failed synthetic ingress probe inventory; bounded categories only."""
import hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_unix_admin_canary_probe_start as probe
DONE=old.ETC/'unix-admin-canary-failure-inventory.json'
STAGES=('unix-admin-canary-orchestration-started.json','unix-admin-canary-epoch2-complete.json','unix-admin-sdk-v4-preflight-complete.json','unix-admin-canary-v4-old-start-complete.json','unix-admin-canary-snapshot-prezero-old-complete.json','unix-admin-canary-v4-register-old-started.json','unix-admin-canary-v4-register-old-complete.json','unix-admin-canary-ingress-probe-started.json','unix-admin-canary-before-retirement.json','unix-admin-canary-v4-retirement-started.json','unix-admin-canary-v4-register-new-started.json','unix-admin-canary-orchestration-complete.json')
CATEGORIES=('identity unavailable','privileges unavailable','ingress outcome unknown','send outcome unknown','send receipt unavailable','original discovery connection unavailable','original discovery reuse unavailable','original ingress connection unavailable','original ingress reuse unavailable','marker unavailable','marker ACL unavailable','direct discovery unavailable','positive mutation unavailable','schedule unavailable','invocation identity or ingress connection unavailable','existing connection outcome unknown','new connection outcome unknown','invocation identity or ingress connection changed')
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'inventory already recorded')
 e=probe.epoch();unit=active.properties(probe.UNIT);require(unit.get('LoadState')=='loaded' and unit.get('Names')==probe.UNIT and unit.get('ActiveState')=='failed' and unit.get('MainPID')=='0' and unit.get('Job','')=='' and unit.get('ControlGroup','')=='','probe not terminal')
 require(unit.get('User')=='sfgoose-control' and unit.get('NoNewPrivileges')=='yes' and unit.get('CapabilityBoundingSet')=='' and unit.get('PrivateNetwork')=='yes' and unit.get('JoinsNamespaceOf')==base.NET and unit.get('DropInPaths','')=='' and unit.get('ExecStart','').startswith('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+str(probe.PROBE)+' ; ignore_errors=no ;'),'probe identity unavailable')
 old.read(probe.PROBE,0o755,probe.PROBE_SHA,65536)
 fd=os.open(probe.LOG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2000,1,0o620) and s.st_size<=16384,'log unavailable');old.noacl(fd);raw=os.read(fd,16385);require(len(raw)==s.st_size,'log changed')
 finally:os.close(fd)
 lines=raw.decode('utf-8','strict').splitlines();known=[x for x in CATEGORIES if any(line=='RuntimeError: '+x for line in lines)]
 frames=[]
 for line in lines:
  m=re.fullmatch(r'  File "[^"]*/unix-admin-canary-ingress-probe-v2.py", line ([0-9]+), in ([A-Za-z0-9_<>]+)',line)
  if m:frames.append({'line':int(m.group(1)),'function':m.group(2)})
 category=known[0] if len(known)==1 else 'unclassified'
 if category=='unclassified':
  for kind in ('TimeoutError','ConnectionResetError','BrokenPipeError','RemoteDisconnected','ConnectionRefusedError','PermissionError','JSONDecodeError','ValueError','AssertionError','OSError'):
   if any(re.match(r'^(?:[A-Za-z_][A-Za-z_0-9]*\.)*'+kind+r'(?::|$)',line) for line in lines):category=kind;break
 stages={}
 for name in STAGES:
  path=old.ETC/name
  if os.path.lexists(path):data=old.read(path,0o600, maxsize=196608);stages[name]={'present':True,'sha256':hashlib.sha256(data).hexdigest()}
  else:stages[name]={'present':False}
 require(stages[STAGES[0]]['present'] and stages[STAGES[7]]['present'] and not stages[STAGES[8]]['present'] and not stages[STAGES[9]]['present'] and not stages[STAGES[10]]['present'] and not stages[STAGES[11]]['present'],'unexpected stage state')
 return {'schema':1,'epoch_sha256':e,'unit':probe.UNIT,'result':unit.get('Result'),'exit_status':old.ctl('show',probe.UNIT,'-p','ExecMainStatus','--value'),'log_sha256':hashlib.sha256(raw).hexdigest(),'log_size':len(raw),'category':category,'last_fixture_frame':frames[-1] if frames else None,'stages':stages,'scope':'read-only failed synthetic probe diagnosis; no retry'}
def apply(approved):
 require(plan()==approved,'inventory changed');old.store(DONE,base.canonical(approved)+b'\n',0o600);return approved
