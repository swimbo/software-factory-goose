"""Inspect only fixed synthetic probe terminal metadata and output shape."""
import hashlib,json,os,stat
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
DONE=old.ETC/'unix-admin-h2-canary-probe-terminal-diagnostic.json';UNIT='sfactory-unix-admin-h2-canary-ingress-probe.service';LOG=base.HANDSHAKE/'ingress-probe.log'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'diagnostic occupied')
 raw=old.read(old.ETC/'unix-admin-h2-canary-before-retirement.json',0o600);before=json.loads(raw);ret=old.read(old.ETC/'unix-admin-h2-canary-retirement-complete.json',0o600);retirement=json.loads(ret);require(before.get('unit')==UNIT and retirement.get('schema')==1,'fixture receipts unavailable')
 props={n:old.ctl('show',UNIT,'-p',n,'--value') for n in ('ActiveState','MainPID','Job','Result','ExecMainCode','ExecMainStatus','ExecMainStartTimestampMonotonic')};require(props['ActiveState'] in ('inactive','failed') and props['MainPID']=='0' and props['Job']=='','unit not terminal')
 fd=os.open(LOG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2000,1,0o620) and st.st_size<=16384,'log unavailable');data=os.read(fd,16385);require(len(data)==st.st_size,'log changed')
 finally:os.close(fd)
 lines=data.splitlines(keepends=True);first_matches=bool(lines) and hashlib.sha256(lines[0]).hexdigest()==before.get('stdout_sha256');stages=[]
 for line in lines:
  try:item=json.loads(line)
  except (ValueError,UnicodeDecodeError):continue
  if isinstance(item,dict) and item.get('stage') in ('before_retirement','after_retirement'):stages.append({'stage':item['stage'],'old_denied':item.get('old_connection_denied') is True,'new_denied':item.get('new_connection_denied') is True,'forwarded_present':isinstance(item.get('forwarded'),str),'effect_expected':item.get('effect')=='requires journal inspection'})
 return {'schema':1,'before_sha256':base.sha(raw),'retirement_sha256':base.sha(ret),'properties':props,'original_start_matches':props['ExecMainStartTimestampMonotonic']==str(before['start_monotonic_us']),'first_line_matches':first_matches,'log_sha256':base.sha(data),'line_count':len(lines),'stages':stages,'scope':'sanitized fixed synthetic output metadata; no query'}
def apply(approved):
 require(plan()==approved,'diagnostic changed');old.store(DONE,base.canonical(approved)+b'\n',0o600);return approved
