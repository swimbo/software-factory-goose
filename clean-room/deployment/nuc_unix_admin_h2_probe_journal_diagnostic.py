"""Bounded PID1 journal metadata for one synthetic probe invocation."""
import json,os,re,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
UNIT='sfactory-unix-admin-h2-canary-ingress-probe.service';DONE=old.ETC/'unix-admin-h2-canary-probe-journal-diagnostic.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'diagnostic occupied');raw=old.read(old.ETC/'unix-admin-h2-canary-before-retirement.json',0o600);before=json.loads(raw);inv=before.get('invocation_id');require(before.get('unit')==UNIT and isinstance(inv,str) and re.fullmatch(r'[0-9a-f]{32}',inv),'invocation unavailable')
 p=subprocess.run(['/usr/bin/journalctl','--boot','--unit='+UNIT,'--no-pager','--output=json','--lines=200'],env=old.ENV,capture_output=True,timeout=15,check=False);require(p.returncode==0 and len(p.stdout)<=1048576 and len(p.stderr)<=8192,'journal unavailable')
 records=[]
 for line in p.stdout.splitlines():
  item=json.loads(line);require(isinstance(item,dict),'journal invalid')
  if item.get('_PID')!='1' or item.get('UNIT')!=UNIT:continue
  identity=item.get('OBJECT_SYSTEMD_INVOCATION_ID',item.get('INVOCATION_ID'));matched=identity==inv
  if not matched:continue
  keys=('MESSAGE_ID','EXIT_CODE','EXIT_STATUS','RESULT','UNIT','_PID','OBJECT_SYSTEMD_INVOCATION_ID','INVOCATION_ID')
  clean={k:item[k] for k in keys if k in item and k not in ('OBJECT_SYSTEMD_INVOCATION_ID','INVOCATION_ID') and isinstance(item[k],str) and re.fullmatch(r'[AA-Za-z0-9_.@:-]{1,128}',item[k])}
  clean['exact_invocation']=True;records.append(clean)
 return {'schema':1,'before_sha256':base.sha(raw),'matching_pid1_records':records,'query_complete':True,'scope':'bounded current boot PID1 metadata only; no messages or IDs'}
def apply(approved):
 require(plan()==approved,'journal changed');old.store(DONE,base.canonical(approved)+b'\n',0o600);return approved
