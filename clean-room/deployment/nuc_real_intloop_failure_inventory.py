"""Read-only inventory after the fixed INT-LOOP launch returned unknown."""
import hashlib,json,os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
G='01M65NEH5T767H8Q5X71TTFR5S';LOW=G.lower();STATE=pathlib.Path('/var/lib/software-factory-goose/stop');CG=pathlib.Path('/sys/fs/cgroup')/('sfactory'+LOW+'.slice')
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def make_plan(host):
 if os.geteuid()!=0:raise RuntimeError('root required')
 old.directory(STATE,0,0,0o700)
 files={}
 for name in sorted(os.listdir(STATE)):
  if not name.startswith(G+'.'):continue
  if len(files)>=100 or len(name)>255:raise RuntimeError('inventory bound')
  path=STATE/name;s=os.lstat(path);entry={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'type':stat.S_IFMT(s.st_mode),'size':s.st_size}
  if stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=65536:
   raw=old.read(path,0o600);entry['sha256']=hashlib.sha256(raw).hexdigest()
  files[name]=entry
 units={}
 for stage in ('submit','pull','grant','launch','stop'):
  name='sfactory-intloop-'+stage+'-'+LOW+'.service';out=old.ctl('show',name,'--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,MainPID,ControlGroup,InvocationID','--no-pager');units[stage]=dict(line.split('=',1) for line in out.splitlines())
 name='sfactory-intloop-launch-'+LOW+'.service';p=subprocess.run(['/usr/bin/journalctl','--boot','-u',name,'--no-pager','-o','cat'],env=old.ENV,capture_output=True,timeout=10,check=True)
 if len(p.stdout)>65536 or len(p.stderr)>8192:raise RuntimeError('journal bound')
 log=p.stdout.decode('utf8','replace');categories=['deadline','expired','permission denied','operation not permitted','not found','refused','cgroup','catalog','scope','helper','systemd','error','failed','timeout','unknown']
 matched=[x for x in categories if x in log.lower()]
 errors=[line for line in log.splitlines() if re.fullmatch(r'Error: [A-Za-z0-9 _.,:;()/-]{1,160}',line)]
 if len(errors)>4:raise RuntimeError('error line bound')
 st=os.stat(CG);events=(CG/'cgroup.events').read_text();require=(st.st_dev,st.st_ino)==(29,7663196) and len(events)<=1024
 if not require:raise RuntimeError('cgroup identity mismatch')
 return {'component':'real-intloop-failure-inventory','source_sha256':host.source_digest,'files':files,'units':units,'launch_log_categories':matched,'fixed_error_lines':errors,'launch_log_bytes':len(p.stdout),'cgroup_events':events.splitlines(),'provider_called':'not established','retries':False}
