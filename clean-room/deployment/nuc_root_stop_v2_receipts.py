"""Read-only inventory of held-launch-lock native canary receipts."""
import json,os,pathlib,re,stat
STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
ROOT=pathlib.Path('/etc/software-factory-goose/tasks')
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 results=[]
 for path in sorted(STATE.glob('*.canary-receipt.json')):
  s=path.lstat()
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:raise RuntimeError('receipt identity mismatch')
  record=json.loads(path.read_text())
  if record.get('launch_lock_held_during_stop') is not True:continue
  target=record.get('target_id','')
  if not re.fullmatch('[0-7][0-9A-HJKMNP-TV-Z]{25}',target) or path.name!=target+'.canary-receipt.json':raise RuntimeError('receipt target mismatch')
  catalogue=ROOT/(target+'.json');closed=STATE/(target+'.closed')
  for p in (catalogue,closed):
   t=p.lstat()
   if not stat.S_ISREG(t.st_mode) or t.st_uid!=0 or t.st_gid!=0 or t.st_nlink!=1 or stat.S_IMODE(t.st_mode)!=0o600:raise RuntimeError('retained record identity mismatch')
  results.append({'receipt':str(path),'record':record,'catalogue':str(catalogue),'closed':str(closed)})
 return {'component':'root-stop-v2-receipts','source_sha256':host.source_digest,'receipts':results}
