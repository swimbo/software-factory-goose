"""Bounded read-only status of the first synthetic SDK5 discovery attempt."""
import json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
import nuc_sdk5_discovery_native_canary as fixture

def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(fixture.DONE),'unexpected canary state')
 intent=old.read(fixture.START,0o600);expected=json.loads(intent);require(expected.get('probe',{}).get('sha256')==fixture.probe.SOURCE_SHA and expected.get('server',{}).get('sha256')==fixture.SERVER_SHA,'canary intent mismatch')
 units={}
 for unit in (fixture.NET,fixture.SERVER_UNIT,fixture.NS,fixture.CHECK,fixture.POS,fixture.NEG):
  fields={key:old.ctl('show',unit,'-p',key,'--value') for key in ('LoadState','ActiveState','MainPID','Job','InvocationID','Result','ExecMainCode','ExecMainStatus','ControlGroup')}
  require(len(str(fields))<=4096,'unit state oversized');units[unit]=fields
 positive=units[fixture.POS];inv=positive['InvocationID'];require(re.fullmatch('[0-9a-f]{32}',inv) is not None and inv!='0'*32,'positive invocation unavailable')
 p=subprocess.run(['/usr/bin/journalctl','--boot','--no-pager','--output=cat','--unit='+fixture.POS,'_SYSTEMD_INVOCATION_ID='+inv],env=old.ENV,capture_output=True,timeout=15,check=False);require(p.returncode==0 and len(p.stdout)<=16384 and len(p.stderr)<=4096,'journal unavailable')
 text=p.stdout.decode('utf-8','replace');categories=('fixture UID/GID unavailable','capabilities not empty','no-new-privileges required','identity fields invalid','descriptor inventory unavailable','unexpected inherited descriptor','stdin unavailable','supervisor pipe unavailable','discovery unavailable','service scope unavailable')
 return {'schema':1,'intent_sha256':fixture.backup.sha(intent),'units':units,'journal_bytes':len(p.stdout),'journal_categories':[x for x in categories if x in text],'scope':'read-only synthetic failure inventory; no retry or cleanup'}
def apply(_):raise RuntimeError('read-only inventory only')
