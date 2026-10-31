"""Summarize protected synthetic failure evidence without replay or raw logs."""
import hashlib,json,os,re,stat
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_probe_start as probe

def require(value,message):
 if not value: raise RuntimeError(message)

def plan():
 require(os.geteuid()==0,'root required')
 inventory=json.loads(old.read(old.ETC/'unix-admin-canary-failure-inventory.json',0o600,maxsize=196608))
 raw=old.read(old.ETC/'unix-admin-canary-snapshot-failure-complete.json',0o600,maxsize=196608)
 snapshot=json.loads(raw)
 require(snapshot.get('schema')==1 and snapshot.get('role')=='failure' and snapshot.get('epoch_sha256')==inventory.get('epoch_sha256'),'snapshot binding mismatch')
 result=snapshot.get('result',{}); rows=result.get('rows',{})
 require(result.get('schema')==1 and result.get('operation')=='snapshot' and set(rows)=={'invocations','queue','state'} and all(isinstance(v,list) and len(v)<=100 for v in rows.values()),'snapshot invalid')
 fd=os.open(probe.LOG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2000,1,0o620) and s.st_size<=16384,'log invalid');old.noacl(fd);log=os.read(fd,16385);require(len(log)==s.st_size and hashlib.sha256(log).hexdigest()==inventory.get('log_sha256'),'log changed')
 finally:os.close(fd)
 frames=[]
 for line in log.decode('utf-8','strict').splitlines():
  m=re.fullmatch(r'  File "[^\"]*/unix-admin-canary-ingress-probe-v2.py", line ([0-9]+), in ([A-Za-z0-9_<>]+)',line)
  if m:frames.append({'line':int(m.group(1)),'function':m.group(2)})
 states={}
 for item in rows['state']:
  require(isinstance(item,dict) and set(item)=={'service_key','key','value_utf8'} and item['service_key'] in ('history','scheduler','blocked','delayed','after') and item['key']=='count' and isinstance(item['value_utf8'],str) and re.fullmatch(r'[0-9]{1,8}',item['value_utf8']) and item['service_key'] not in states,'state unknown')
  states[item['service_key']]=int(item['value_utf8'])
 return {'schema':1,'epoch_sha256':inventory['epoch_sha256'],'snapshot_sha256':hashlib.sha256(raw).hexdigest(),'category':inventory['category'],'fixture_frames':frames,'invocation_count':len(rows['invocations']),'queue_count':len(rows['queue']),'synthetic_counts':states,'scope':'protected synthetic evidence only; no replay or mutation'}

def apply(approved):
 require(plan()==approved,'summary changed')
 path=old.ETC/'unix-admin-canary-failure-summary.json'
 require(not os.path.lexists(path),'summary already recorded')
 old.store(path,(json.dumps(approved,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
 return approved
