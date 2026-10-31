"""Recover exact prior probe result from protected log and PID1 invocation journal."""
import hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_unix_admin_h2_activate as active
import nuc_unix_admin_h2_sdk_install as package
import nuc_unix_admin_h2_probe_start as before
import nuc_unix_admin_h2_probe_journal_diagnostic as journal
import nuc_unix_admin_h2_probe_terminal_diagnostic as terminal_diag
OUT=old.ETC/'unix-admin-h2-canary-after-retirement.json';START=old.ETC/'unix-admin-h2-canary-probe-after-recovery-started.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def terminal(before_raw):
 j=json.loads(old.read(journal.DONE,0o600));require(j.get('schema')==1 and j.get('before_sha256')==hashlib.sha256(before_raw).hexdigest() and j.get('query_complete') is True and isinstance(j.get('matching_pid1_records'),list),'journal evidence unavailable')
 records=j['matching_pid1_records'];success=[r for r in records if isinstance(r,dict) and r.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' and r.get('UNIT')==before.UNIT and r.get('_PID')=='1' and r.get('exact_invocation') is True];require(len(success)==1,'unit success unavailable')
 require(old.ctl('show',before.UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',before.UNIT,'-p','Job','--value')=='','unit not terminal')
 cg=pathlib.Path('/sys/fs/cgroup/system.slice')/before.UNIT
 if cg.exists():
  st=cg.stat();require(st.st_uid==0 and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'probe cgroup unavailable')
 return j
def plan():
 require(os.geteuid()==0 and not os.path.lexists(OUT) and not os.path.lexists(START),'receipt occupied')
 raw=old.read(before.DONE,0o600);b=json.loads(raw);require(b.get('schema')==1 and b.get('unit')==before.UNIT and b.get('probe_source_sha256')==before.PROBE_SHA and b.get('probe_active') is True and b.get('no_job') is True,'before proof unavailable')
 require(before.epoch()==b['epoch_sha256'],'fixture epoch changed');old.read(before.PROBE,0o755,before.PROBE_SHA,65536)
 terminal(raw)
 fd=os.open(before.LOG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2000,1,0o620) and st.st_size<=16384,'probe log unavailable');data=os.read(fd,16385);require(len(data)==st.st_size,'probe log changed')
 finally:os.close(fd)
 diagnostic=json.loads(old.read(terminal_diag.DONE,0o600));require(diagnostic.get('before_sha256')==hashlib.sha256(raw).hexdigest() and diagnostic.get('first_line_matches') is True and diagnostic.get('line_count')==2 and diagnostic.get('log_sha256')==hashlib.sha256(data).hexdigest(),'terminal diagnostic changed')
 lines=data.splitlines(keepends=True);require(len(lines)==2 and all(line.endswith(b'\n') for line in lines) and hashlib.sha256(lines[0]).hexdigest()==b['stdout_sha256'],'probe output changed')
 obj=json.loads(lines[1]);require(set(obj)=={'stage','old_connection_denied','new_connection_denied','forwarded','effect'} and obj['stage']=='after_retirement' and obj['old_connection_denied'] is True and obj['new_connection_denied'] is True and obj['effect']=='requires journal inspection' and isinstance(obj['forwarded'],str) and re.fullmatch(r'[A-Za-z0-9_-]{1,256}',obj['forwarded']) and obj['forwarded'] not in (b['hold'],b['queued']),'after result unavailable')
 return {'schema':1,'epoch_sha256':b['epoch_sha256'],'probe_source_sha256':b['probe_source_sha256'],'unit':before.UNIT,'pid':b['pid'],'invocation_id':b['invocation_id'],'stdout_sha256':hashlib.sha256(data).hexdigest(),**obj,'probe_terminal':True,'no_job':True}
def apply(reviewed):
 require(plan()==reviewed,'result changed');old.store(START,json.dumps(reviewed,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);old.store(OUT,json.dumps(reviewed,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return reviewed
