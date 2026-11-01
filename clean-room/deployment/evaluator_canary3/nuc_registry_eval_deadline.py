"""Fixed per-evaluation independent stop timer, source candidate only."""
import ctypes,os,pathlib,re,stat,sys,time
from nuc_registry_eval_broker import Unavailable
STATE=pathlib.Path('/var/lib/software-factory-goose/stop');TASKS=pathlib.Path('/etc/software-factory-goose/tasks');CG=pathlib.Path('/sys/fs/cgroup')
class Deadline:
 def __init__(self,base,catalog):self.base=base;self.catalog=catalog
 def plan(self,target):
  if sys.platform!='linux' or os.uname().machine!='x86_64':raise Unavailable('platform unavailable')
  d=self.base;matches=[x for x in self.catalog['challenges'] if x['target']==target]
  if len(matches)!=1:raise Unavailable('target unavailable')
  e=matches[0];d.fixed_binary();task,task_sha=d.pinned_json(TASKS/(target+'.json'));boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  if task!={'schema':1,'target_id':target,'task_id':e['task_id'],'generation':target,'boot_id':boot,'cgroup_dev':e['cgroup_dev'],'cgroup_ino':e['cgroup_ino']} or boot!=self.catalog['boot_id']:raise Unavailable('task binding unavailable')
  cg=CG/('sfactory'+target.lower()+'.slice');fd=os.open(cg,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);fs=ctypes.create_string_buffer(256);libc=ctypes.CDLL(None,use_errno=True)
   if libc.fstatfs(fd,ctypes.byref(fs))!=0 or ctypes.c_long.from_buffer(fs).value!=0x63677270 or not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_mode&0o022:raise Unavailable('cgroup unavailable')
  finally:os.close(fd)
  if (st.st_dev,st.st_ino)!=(e['cgroup_dev'],e['cgroup_ino']) or os.path.lexists(STATE/(target+'.closed')) or os.path.lexists(STATE/(target+'.eval-deadline-intent.json')):raise Unavailable('deadline unavailable')
  timer='sfactorydeadline'+target.lower()+'.timer';service='sfactorydeadline'+target.lower()+'.service'
  for name in (timer,service):
   if d.property_value(name,'LoadState') not in ('','not-found'):raise Unavailable('timer occupied')
  return {'target':target,'boot_id':boot,'task_sha256':task_sha,'timer':timer,'service':service,'purpose':'evaluation-challenge-v1'}
 def arm(self,spec):
  d=self.base
  if self.plan(spec['target'])!=spec:raise Unavailable('deadline changed')
  target=spec['target'];before=time.monotonic_ns();d.store(STATE/(target+'.eval-deadline-intent.json'),spec)
  d.run('/usr/bin/systemd-run','--unit='+spec['service'][:-8],'--on-active=35s','--timer-property=AccuracySec=1ms','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=RestrictAddressFamilies=AF_UNIX','--property=MemoryMax=128M','--property=TasksMax=16','--property=CPUQuota=50%','--property=ReadWritePaths=/var/lib/software-factory-goose/stop /sys/fs/cgroup','--property=TimeoutStartSec=12s','--property=Restart=on-failure','--property=RestartSec=1s','--property=StartLimitIntervalSec=0',str(d.BINARY),target)
  d.verify_units(spec)
  if d.property_value(spec['timer'],'ActiveState')!='active':raise Unavailable('timer unavailable')
  wake=d.run('/usr/bin/busctl','get-property','org.freedesktop.systemd1',d.unit_path(spec['timer']),'org.freedesktop.systemd1.Timer','NextElapseUSecMonotonic')
  if not re.fullmatch(r't [0-9]+',wake):raise Unavailable('wake unavailable')
  ns=int(wake[2:])*1000
  if not time.monotonic_ns()<ns<=before+40_000_000_000:raise Unavailable('wake unavailable')
  result={'target':target,'timer':spec['timer'],'wake_monotonic_ns':ns};d.store(STATE/(target+'.eval-deadline-armed.json'),result);return result
 def run(self,*args,**kwargs):return self.base.run(*args,**kwargs)
