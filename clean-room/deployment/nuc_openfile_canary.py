"""Fixed public OpenFile installation and single owned-unit observation."""
import time
_INSTALL=apply
_PLAN=plan
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 spec,_,_=_PLAN()
 return {'component':'openfile-public-canary','source_sha256':host.source_digest,'spec':spec,'after_install':'reload-manager-and-start-only-sfactory-openfile-public-canary.service-once'}

def ctl(*args):
 return subprocess.run(['/usr/bin/systemctl',*args],capture_output=True,text=True,check=True,timeout=20)

def apply(host,reviewed):
 if make_plan(host)!=reviewed:raise RuntimeError('reviewed public probe changed')
 outcome=_INSTALL(reviewed['spec'])
 ctl('daemon-reload')
 # Durable installed intent precedes this unique, never-retried activation.
 create(LEDGER/'start-intent.json',b'{"public_only":true}\n',0o600)
 ctl('start',UNIT.name)
 result=ctl('show',UNIT.name,'-p','Result','-p','ExecMainStatus','-p','ActiveState').stdout
 props=dict(line.split('=',1) for line in result.splitlines() if '=' in line)
 if props!={'Result':'success','ExecMainStatus':'0','ActiveState':'inactive'}:raise RuntimeError('public probe result unresolved')
 r=subprocess.run(['/usr/bin/journalctl','-b','-u',UNIT.name,'--no-pager','-o','json'],capture_output=True,text=True,check=True,timeout=10)
 if len(r.stdout.encode())>65536:raise RuntimeError('public probe journal exceeds bound')
 hits=[]
 for line in r.stdout.splitlines():
  obj=json.loads(line)
  if obj.get('_SYSTEMD_UNIT')!=UNIT.name or obj.get('_UID')!='2000':continue
  try:message=json.loads(obj['MESSAGE'])
  except (ValueError,TypeError,KeyError):continue
  expected={'public_sha256':hashlib.sha256(PUBLIC).hexdigest(),'uid':2000,'root_readonly_fd':True,'network_identity_matched':True}
  if message!=expected:raise RuntimeError('public probe observation mismatch')
  hits.append({'observation':message,'invocation_id':obj['_SYSTEMD_INVOCATION_ID']})
 if len(hits)!=1:raise RuntimeError('public probe observation missing or duplicated')
 receipt={'status':'public_openfile_and_host_namespace_passed','observation':hits[0], 'provider_credential_access':False,'production_accepted':False}
 create(LEDGER/'observed.json',json.dumps(receipt,sort_keys=True).encode(),0o600)
 return receipt
