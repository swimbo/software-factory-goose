#!/usr/bin/env python3
"""Review-only fixed root deadline arm; no production grant or automatic cleanup.

A root-owned synthetic grant must be provisioned independently. Every ambiguous
manager result retains intent and denies launch. This script does not create a
cgroup, provision a grant, start Docker, or resolve reboot/manager-loss recovery.
"""
import hashlib,json,os,pathlib,re,stat,subprocess,sys,time
ROOT=pathlib.Path('/etc/software-factory-goose/tasks')
GRANTS=pathlib.Path('/etc/software-factory-goose/deadline-grants')
STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
CGROUP=pathlib.Path('/sys/fs/cgroup')
BINARY=pathlib.Path('/usr/local/libexec/software-factory-goose/sfactory_deadline_kernel_stop')
BINARY_SHA='e286a8daab464f29e14e11beed0147cf24a11b585b4dfc50e48cb8615d0a325a'
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0','LC_ALL':'C'}
MAX_SECONDS=120

def run(*argv,timeout=10):
 p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,env=ENV)
 if p.returncode:raise RuntimeError('fixed manager query failed')
 if len(p.stdout)>65536:raise RuntimeError('manager output too large')
 return p.stdout.strip()

def private_dir(p):
 s=p.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=0o700:raise RuntimeError('untrusted directory')
 for parent in p.parents:
  m=parent.lstat()
  if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_gid!=0 or m.st_mode&0o022:raise RuntimeError('untrusted ancestor')

def pinned_json(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>4096:raise RuntimeError('untrusted record')
  raw=f.read(4097)
  if len(raw)!=s.st_size or len(raw)>4096 or f.read(1):raise RuntimeError('record length changed')
 return json.loads(raw),hashlib.sha256(raw).hexdigest()

def canonical(s):
 if not isinstance(s,str) or not re.fullmatch('[0-7][0-9A-HJKMNP-TV-Z]{25}',s):raise RuntimeError('invalid generation')
 return s

def fixed_binary():
 fd=os.open(BINARY,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno())
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o755:raise RuntimeError('binary metadata')
  if hashlib.sha256(f.read(64*1024*1024+1)).hexdigest()!=BINARY_SHA:raise RuntimeError('binary digest')

def unit_path(unit):
 # systemd object-path escape for the fixed ASCII unit name.
 return '/org/freedesktop/systemd1/unit/'+''.join(c if c.isascii() and c.isalnum() else '_%02x'%ord(c) for c in unit)

def property_value(unit,key):
 return run('/usr/bin/systemctl','show',unit,'-p',key,'--value')

def verify_units(spec):
 for unit in (spec['timer'],spec['service']):
  expected={'LoadState':'loaded','Transient':'yes','Names':unit,'FragmentPath':'/run/systemd/transient/'+unit,'DropInPaths':''}
  for key,value in expected.items():
   if property_value(unit,key)!=value:raise RuntimeError('unit identity mismatch: '+key)
 for key,value in {'User':'root','Group':'root','NoNewPrivileges':'yes','CapabilityBoundingSet':'','TasksMax':'16','MemoryMax':'134217728','CPUQuotaPerSecUSec':'500ms','RestrictAddressFamilies':'AF_UNIX','Restart':'on-failure','StartLimitIntervalUSec':'0'}.items():
  if property_value(spec['service'],key)!=value:raise RuntimeError('service property mismatch: '+key)
 if property_value(spec['timer'],'Unit')!=spec['service']:raise RuntimeError('timer target mismatch')
 command=property_value(spec['service'],'ExecStart')
 prefix='{ path='+str(BINARY)+' ; argv[]='+str(BINARY)+' '+spec['target']+' ; ignore_errors=no ;'
 if not command.startswith(prefix) or command.count('{ path=')!=1:raise RuntimeError('deadline command mismatch')

def validate(grant,cat,g,boot,now):
 expected={'schema','target_id','boot_id','catalog_sha256','issued_unix_ns','expires_unix_ns','max_duration_seconds','purpose'}
 if set(grant)!=expected or grant['schema']!=1 or grant['target_id']!=g or grant['boot_id']!=boot or grant['purpose']!='synthetic-canary-only':raise RuntimeError('grant scope')
 if not re.fullmatch('[0-9a-f]{64}',grant['catalog_sha256']):raise RuntimeError('bad catalog digest')
 if set(cat)!={'schema','target_id','task_id','generation','boot_id','cgroup_dev','cgroup_ino'} or type(cat['schema']) is not int or cat['schema']!=1 or cat['target_id']!=g or cat['generation']!=g or cat['boot_id']!=boot:raise RuntimeError('catalog scope')
 canonical(cat['task_id'])
 if any(type(cat[k]) is not int or cat[k]<=0 for k in ('cgroup_dev','cgroup_ino')):raise RuntimeError('catalog cgroup identity')
 issued=grant['issued_unix_ns'];expiry=grant['expires_unix_ns'];cap=grant['max_duration_seconds']
 if any(type(x) is not int for x in (issued,expiry,cap)) or not 1<=cap<=MAX_SECONDS or not issued<=now<expiry or expiry-issued>MAX_SECONDS*1_000_000_000:raise RuntimeError('expiry invalid')
 # Subtract five seconds for the manager operation; verify the actual scheduled
 # monotonic elapse after start. Failure retains intent and never admits launch.
 duration=min(cap,(expiry-now)//1_000_000_000)-5
 if duration<1:raise RuntimeError('insufficient deadline margin')
 return duration

def plan(g):
 canonical(g)
 for d in (ROOT,GRANTS,STATE):private_dir(d)
 fixed_binary();grant,grant_sha=pinned_json(GRANTS/(g+'.json'));cat,cat_sha=pinned_json(ROOT/(g+'.json'))
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();duration=validate(grant,cat,g,boot,time.time_ns())
 if grant['catalog_sha256']!=cat_sha:raise RuntimeError('catalog digest mismatch')
 cg=CGROUP/('sfactory'+g.lower()+'.slice');st=cg.stat()
 if not cg.is_dir() or st.st_dev!=cat['cgroup_dev'] or st.st_ino!=cat['cgroup_ino']:raise RuntimeError('cgroup identity mismatch')
 if os.path.lexists(STATE/(g+'.closed')) or os.path.lexists(STATE/(g+'.deadline-intent.json')):raise RuntimeError('closed or prior intent')
 unit='sfactorydeadline'+g.lower();timer=unit+'.timer';service=unit+'.service'
 for n in (timer,service):
  if run('/usr/bin/systemctl','show',n,'-p','LoadState','--value') not in ('','not-found'):raise RuntimeError('unit exists')
 return {'target':g,'boot_id':boot,'grant_sha256':grant_sha,'catalog_sha256':cat_sha,'binary_sha256':BINARY_SHA,'duration_seconds':duration,'expires_unix_ns':grant['expires_unix_ns'],'timer':timer,'service':service,'purpose':'synthetic-canary-only'}

def store(path,obj):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'w') as f:json.dump(obj,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def arm(spec):
 g=spec['target'];current=plan(g)
 # Duration can shrink as real time advances; all immutable scope must match.
 for k in ('target','boot_id','grant_sha256','catalog_sha256','binary_sha256','expires_unix_ns','timer','service','purpose'):
  if current[k]!=spec[k]:raise RuntimeError('reviewed scope changed')
 duration=min(spec['duration_seconds'],current['duration_seconds'])
 before_mono=time.monotonic_ns();before_wall=time.time_ns()
 store(STATE/(g+'.deadline-intent.json'),{'spec':spec,'selected_duration_seconds':duration})
 # Never assume a timed-out or failed systemd-run cancelled its server-side effect.
 run('/usr/bin/systemd-run','--unit='+spec['service'][:-8], '--on-active='+str(duration)+'s','--timer-property=AccuracySec=1ms','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=RestrictAddressFamilies=AF_UNIX','--property=MemoryMax=128M','--property=TasksMax=16','--property=CPUQuota=50%','--property=ReadWritePaths=/var/lib/software-factory-goose/stop /sys/fs/cgroup','--property=TimeoutStartSec=12s','--property=Restart=on-failure','--property=RestartSec=1s','--property=StartLimitIntervalSec=0',str(BINARY),g)
 verify_units(spec)
 if run('/usr/bin/systemctl','show',spec['timer'],'-p','ActiveState','--value')!='active':raise RuntimeError('timer not active')
 value=run('/usr/bin/busctl','get-property','org.freedesktop.systemd1',unit_path(spec['timer']),'org.freedesktop.systemd1.Timer','NextElapseUSecMonotonic')
 if not re.fullmatch(r't [0-9]+',value):raise RuntimeError('timer wake unavailable')
 wake=int(value[2:])*1000;now_mono=time.monotonic_ns();now_wall=time.time_ns()
 if now_wall<before_wall or abs((now_wall-before_wall)-(now_mono-before_mono))>1_000_000_000 or not now_mono<wake<=before_mono+(spec['expires_unix_ns']-before_wall):raise RuntimeError('deadline or clock uncertain')
 store(STATE/(g+'.deadline-armed.json'),{'target':g,'boot_id':spec['boot_id'],'grant_sha256':spec['grant_sha256'],'wake_monotonic_ns':wake,'engine_effects':False})
 return {'target':g,'wake_monotonic_ns':wake,'timer':spec['timer'],'status':'armed_not_admitted'}

def main():
 if os.geteuid()!=0 or len(sys.argv)!=3 or sys.argv[1] not in ('plan','apply'):raise RuntimeError('root plan/apply and canonical target required')
 g=canonical(sys.argv[2]);spec=plan(g)
 if sys.argv[1]=='plan':print(json.dumps(spec,sort_keys=True));return
 # Applying by target is deliberately disabled until plan binding is implemented.
 raise RuntimeError('apply disabled pending reviewed immutable plan binding')
if __name__=='__main__':main()
