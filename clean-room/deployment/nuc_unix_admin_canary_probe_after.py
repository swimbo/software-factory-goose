"""Persist bounded result of the fixed synthetic post-retirement probe."""
import hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_activate as active
import nuc_unix_admin_canary_sdk_install as package
import nuc_unix_admin_canary_probe_start as before
OUT=old.ETC/'unix-admin-canary-after-retirement.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(OUT),'receipt occupied')
 raw=old.read(before.DONE,0o600);b=json.loads(raw);require(b.get('schema')==1 and b.get('unit')==before.UNIT and b.get('probe_source_sha256')==before.PROBE_SHA and b.get('probe_active') is True and b.get('no_job') is True,'before proof unavailable')
 require(before.epoch()==b['epoch_sha256'],'fixture epoch changed');old.read(before.PROBE,0o755,before.PROBE_SHA,65536)
 for prop,value in (('ActiveState','inactive'),('MainPID','0'),('Job',''),('Result','success'),('ExecMainCode','1'),('ExecMainStatus','0'),('ExecMainStartTimestampMonotonic',str(b['start_monotonic_us']))):require(old.ctl('show',before.UNIT,'-p',prop,'--value')==value,'probe outcome unknown')
 state=active.properties(before.UNIT);require(state.get('Names')==before.UNIT and state.get('DropInPaths','')=='' and state.get('User')=='sfgoose-control' and state.get('Group')=='sfgoose-control' and state.get('PrivateNetwork')=='yes' and state.get('JoinsNamespaceOf')==base.NET and state.get('BindsTo')==base.NET and state.get('ExecStart','').startswith('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+str(before.PROBE)+' ; ignore_errors=no ;') and state['ExecStart'].count('{ path=')==1,'probe identity unavailable')
 fd=os.open(before.LOG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2000,1,0o620) and st.st_size<=16384,'probe log unavailable');data=os.read(fd,16385);require(len(data)==st.st_size,'probe log changed')
 finally:os.close(fd)
 lines=data.splitlines(keepends=True);require(len(lines)==2 and all(line.endswith(b'\n') for line in lines) and hashlib.sha256(lines[0]).hexdigest()==b['stdout_sha256'],'probe output changed')
 obj=json.loads(lines[1]);require(set(obj)=={'stage','old_connection_denied','new_connection_denied','forwarded','effect'} and obj['stage']=='after_retirement' and obj['old_connection_denied'] is True and obj['new_connection_denied'] is True and obj['effect']=='requires journal inspection' and isinstance(obj['forwarded'],str) and re.fullmatch(r'[A-Za-z0-9_-]{1,256}',obj['forwarded']) and obj['forwarded'] not in (b['hold'],b['queued']),'after result unavailable')
 return {'schema':1,'epoch_sha256':b['epoch_sha256'],'probe_source_sha256':b['probe_source_sha256'],'unit':before.UNIT,'pid':b['pid'],'invocation_id':b['invocation_id'],'stdout_sha256':hashlib.sha256(data).hexdigest(),**obj,'probe_terminal':True,'no_job':True}
def apply(reviewed):
 require(plan()==reviewed,'result changed');old.store(OUT,json.dumps(reviewed,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return reviewed
