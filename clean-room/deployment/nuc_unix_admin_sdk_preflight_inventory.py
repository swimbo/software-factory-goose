"""Fixed read-only inventory of the synthetic SDK preflight failure."""
import os,pathlib,stat
import nuc_grant_sidecar_install as old
LOG=pathlib.Path('/var/lib/software-factory-goose/unix-admin-canary/sdk-preflight/startup.log')
UNITS=('sfactory-unix-admin-sdk-preflight.service','sfactory-unix-admin-sdk-preflight-connect.service','sfactory-unix-admin-sdk-preflight-closed.service','sfactory-unix-admin-sdk-preflight-extra-fd.service')
def plan():
 if os.geteuid()!=0:raise RuntimeError('root required')
 fd=os.open(LOG,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);old.noacl(fd)
  if not stat.S_ISREG(st.st_mode) or (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))!=(0,2000,1,0o620) or st.st_size>1048576:raise RuntimeError('log unavailable')
  raw=os.read(fd,1048577)
  if len(raw)!=st.st_size:raise RuntimeError('log changed')
 finally:os.close(fd)
 # Only fixed classifications; never print arbitrary log text.
 categories={name:(pattern in raw) for name,pattern in {'unexpected_descriptor':b'unexpected inherited descriptor','socket_on_stdio':b'socket on stdio forbidden','uid':b'fixture UID/GID unavailable','capabilities':b'capabilities not empty','nnp':b'no-new-privileges required','parse':b'invalid digit found in string','os_permission':b'Permission denied'}.items()}
 units={}
 for unit in UNITS:
  units[unit]={k:old.ctl('show',unit,'-p',k,'--value') for k in ('LoadState','ActiveState','MainPID','Job','Result','ExecMainCode','ExecMainStatus')}
 return {'scope':'read-only synthetic SDK failure inventory','log_bytes':len(raw),'categories':categories,'units':units}
def apply(reviewed):raise RuntimeError('read-only inventory')
