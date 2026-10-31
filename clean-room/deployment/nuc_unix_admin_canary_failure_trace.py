"""Read-only allowlisted stack-frame metadata for the retained failed probe."""
import hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as base
import nuc_unix_admin_canary_failure_inventory as inventory
import nuc_unix_admin_canary_probe_start as probe

DONE=old.ETC/'unix-admin-canary-failure-trace-v2.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def extract_frames(data):
 frames=[]
 for line in data.decode('utf-8','strict').splitlines():
  m=re.fullmatch(r'  File "[^"]*/unix-admin-canary-ingress-probe-v2.py", line ([0-9]+), in ([A-Za-z0-9_<>]+)',line)
  if m:
   n=int(m.group(1));require(0<n<=10000 and len(frames)<16,'frame bounds exceeded');frames.append({'line':n,'function':m.group(2)})
 return frames
def plan():
 require(os.geteuid()==0 and os.getegid()==0 and not os.path.lexists(DONE),'trace unavailable')
 raw=old.read(inventory.DONE,0o600);prior=json.loads(raw)
 require(prior.get('schema')==1 and prior.get('unit')==probe.UNIT and prior.get('category')=='ConnectionResetError' and prior.get('epoch_sha256')==probe.epoch(),'original inventory unavailable')
 fd=os.open(probe.LOG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2000,1,0o620) and st.st_size<=16384,'log metadata invalid');old.noacl(fd)
  data=os.read(fd,16385);require(len(data)==st.st_size and hashlib.sha256(data).hexdigest()==prior['log_sha256'],'retained log changed')
 finally:os.close(fd)
 frames=extract_frames(data)
 require(frames and frames[-1]==prior.get('last_fixture_frame'),'frame provenance unavailable')
 return {'schema':1,'inventory_sha256':hashlib.sha256(raw).hexdigest(),'epoch_sha256':prior['epoch_sha256'],'log_sha256':prior['log_sha256'],'category':prior['category'],'fixture_frames':frames,'scope':'read-only sanitized source locations; no replay'}
def apply(reviewed):
 require(plan()==reviewed,'trace changed');old.store(DONE,base.canonical(reviewed)+b'\n',0o600);return reviewed
