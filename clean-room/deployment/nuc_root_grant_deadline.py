"""Review-only grant-bound root deadline adapter; no production activation.

Bridge must inject the pinned reviewed `deadline` module. Root launch catalogue,
recipe, grant-request and verified-grant files must be pre-existing and private.
A timeout or missing result leaves intent permanently fenced and is never retried.
"""
import ctypes,hashlib,json,os,pathlib,re,time
ROOT=pathlib.Path('/etc/software-factory-goose/launch-catalog')
STOPCAT=pathlib.Path('/etc/software-factory-goose/tasks')
STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
CGROUP=pathlib.Path('/sys/fs/cgroup')
GOOSE='802d1478e6a53ef7c68a56ccfed3aec59eab0afd68aa411ec0c1b516dc5334db'
HEX=re.compile('[0-9a-f]{64}')

def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def record(deadline,path):
 value,sha=deadline.pinned_json(path)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:raw=f.read(4097)
 if len(raw)>4096 or digest(raw)!=sha:raise RuntimeError('record changed')
 return value,raw,sha

def matches(c,recipe,verified,stop,boot,g,now_ms):
 if set(c)!={'schema','scope','boot_id','cgroup_dev','cgroup_ino','recipe_sha256','max_expiry_ms'} or c['schema']!=1 or c['boot_id']!=boot:raise RuntimeError('launch catalogue mismatch')
 if set(verified)!={'schema','generation','binding_sha256','reservation'} or verified['schema']!=1 or verified['generation']!=g:raise RuntimeError('verified grant mismatch')
 grant=verified['reservation'];scope=c['scope']
 if set(grant)!={'scope','generation','attempt','token_sha256','expires_at_ms','hard_deadline_ms'} or grant['scope']!=scope or grant['generation']!=g or type(grant['attempt']) is not int or grant['attempt']<1 or not isinstance(grant['token_sha256'],str) or not HEX.fullmatch(grant['token_sha256']):raise RuntimeError('grant scope mismatch')
 if scope.get('generation')!=g or stop.get('target_id')!=g or stop.get('generation')!=g or stop.get('boot_id')!=boot or (c['cgroup_dev'],c['cgroup_ino'])!=(stop.get('cgroup_dev'),stop.get('cgroup_ino')):raise RuntimeError('cgroup catalogue mismatch')
 fields={'schema','purpose','generation','task_id','worker_uid','goose_binary_sha256','worker_image_id','worker_program_sha256','writer_image_id','writer_program_sha256','profile_sha256','prompt_sha256','relay_scope_template_sha256','provider_binding_sha256','fixed_parent'}
 if set(recipe)!=fields or recipe['schema']!=1 or recipe['purpose']!='nuc-goose-write-files-v1' or recipe['generation']!=g or recipe['task_id']!=scope.get('task_id') or recipe['worker_uid']!=2001 or recipe['goose_binary_sha256']!=GOOSE or recipe['fixed_parent']!='sfactory'+g.lower()+'.slice':raise RuntimeError('recipe mismatch')
 expected={'worker_image_id':'sha256:509d7c54cfdbf6afd9e1c80ff924d367bdaf0979e6ef63b1f7d1134ce3a9710a','writer_image_id':'sha256:2efe778192492f6934540be9771bc1057b4724fe20bed6f71a362a4b91636b48','worker_program_sha256':'c0f51ee7767c6448c1fa3908e137c280753de302af9e7196751bb67fbc601df1','writer_program_sha256':'4ade60e556a391795b8f2b13a5e6d52efb68a04d6d806f5e0bf76e3cdc0d3d8c'}
 if any(recipe[k]!=v for k,v in expected.items()):raise RuntimeError('root-provisioned image or program mismatch')
 for key in ('worker_program_sha256','writer_program_sha256','profile_sha256','prompt_sha256','relay_scope_template_sha256','provider_binding_sha256'):
  if not isinstance(recipe[key],str) or not HEX.fullmatch(recipe[key]):raise RuntimeError('recipe digest mismatch')
 for key in ('worker_image_id','writer_image_id'):
  if not isinstance(recipe[key],str) or not recipe[key].startswith('sha256:') or not HEX.fullmatch(recipe[key][7:]):raise RuntimeError('image identity mismatch')
 if digest(canonical(recipe))!=c['recipe_sha256']:raise RuntimeError('recipe binding mismatch')
 gb=canonical(grant);cb=canonical(c);binding=digest(b'sfactory-root-grant-v1\0'+len(gb).to_bytes(8,'big')+gb+len(cb).to_bytes(8,'big')+cb)
 if binding!=verified['binding_sha256']:raise RuntimeError('full grant binding mismatch')
 expiry=grant['expires_at_ms'];hard=grant['hard_deadline_ms'];limit=c['max_expiry_ms']
 if any(type(x) is not int for x in (expiry,hard,limit)) or not now_ms<expiry<=hard<=limit:raise RuntimeError('grant expired')
 return binding,expiry

def plan(deadline,g):
 deadline.canonical(g)
 for p in (ROOT,STOPCAT,STATE):deadline.private_dir(p)
 deadline.fixed_binary();boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 cat,_,catsha=record(deadline,ROOT/(g+'.json'));recipe,recipe_raw,recipesha=record(deadline,ROOT/(g+'.recipe.json'))
 if recipe_raw!=canonical(recipe):raise RuntimeError('recipe is not canonical')
 stop,_,stopsha=record(deadline,STOPCAT/(g+'.json'));verified,_,grantsha=record(deadline,STATE/(g+'.grant-verified'))
 request=root_request(deadline,g)
 if request!=g+'\n'+cat['scope']['catalog_sha256']+'\n':raise RuntimeError('request intent mismatch')
 now=time.time_ns()//1_000_000;binding,expiry=matches(cat,recipe,verified,stop,boot,g,now)
 if recipesha!=cat['recipe_sha256']:raise RuntimeError('recipe hash changed')
 cg=CGROUP/('sfactory'+g.lower()+'.slice');st=cg.stat()
 if not cg.is_dir() or (st.st_dev,st.st_ino)!=(cat['cgroup_dev'],cat['cgroup_ino']):raise RuntimeError('cgroup identity mismatch')
 # Confirm the pinned cgroup is really on the cgroup2 filesystem.
 class StatFs(ctypes.Structure):_fields_=[('f_type',ctypes.c_long),('rest',ctypes.c_byte*248)]
 fs=StatFs();libc=ctypes.CDLL(None,use_errno=True)
 if libc.statfs(os.fsencode(str(cg)),ctypes.byref(fs))!=0 or fs.f_type!=0x63677270:raise RuntimeError('cgroup2 unavailable')
 if os.path.lexists(STATE/(g+'.closed')) or os.path.lexists(STATE/(g+'.deadline-intent.json')):raise RuntimeError('closed or timer already attempted')
 duration=min(240,(expiry-now)//1000)-5
 if duration<1:raise RuntimeError('deadline margin insufficient')
 timer='sfactorydeadline'+g.lower()+'.timer';service='sfactorydeadline'+g.lower()+'.service'
 for n in (timer,service):
  if deadline.run('/usr/bin/systemctl','show',n,'-p','LoadState','--value') not in ('','not-found'):raise RuntimeError('deadline unit collision')
 return {'target':g,'boot_id':boot,'catalog_sha256':catsha,'recipe_sha256':recipesha,'stop_catalog_sha256':stopsha,'verified_grant_sha256':grantsha,'binding_sha256':binding,'expiry_ms':expiry,'duration_seconds':duration,'timer':timer,'service':service,'purpose':'grant-bound-production-not-activated'}

def root_request(deadline,g):
 path=STATE/(g+'.grant-request');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not __import__('stat').S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or __import__('stat').S_IMODE(s.st_mode)!=0o600 or s.st_size>256:raise RuntimeError('bad intent')
  b=f.read(257)
  if len(b)!=s.st_size or f.read(1):raise RuntimeError('intent changed')
 return b.decode()

def arm(deadline,reviewed):
 current=plan(deadline,reviewed['target'])
 for k in ('target','boot_id','catalog_sha256','recipe_sha256','stop_catalog_sha256','verified_grant_sha256','binding_sha256','expiry_ms','timer','service','purpose'):
  if reviewed[k]!=current[k]:raise RuntimeError('deadline plan changed')
 duration=min(reviewed['duration_seconds'],current['duration_seconds']);g=reviewed['target'];before_mono=time.monotonic_ns();before_wall=time.time_ns()
 deadline.store(STATE/(g+'.deadline-intent.json'),{'reviewed':reviewed,'selected_duration_seconds':duration})
 deadline.run('/usr/bin/systemd-run','--unit='+reviewed['service'][:-8],'--on-active='+str(duration)+'s','--timer-property=AccuracySec=1ms','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=RestrictAddressFamilies=AF_UNIX','--property=MemoryMax=128M','--property=TasksMax=16','--property=CPUQuota=50%','--property=ReadWritePaths=/var/lib/software-factory-goose/stop /sys/fs/cgroup','--property=TimeoutStartSec=12s','--property=Restart=on-failure','--property=RestartSec=1s','--property=StartLimitIntervalSec=0',str(deadline.BINARY),g)
 deadline.verify_units(reviewed)
 if deadline.property_value(reviewed['timer'],'ActiveState')!='active':raise RuntimeError('timer not active')
 value=deadline.run('/usr/bin/busctl','get-property','org.freedesktop.systemd1',deadline.unit_path(reviewed['timer']),'org.freedesktop.systemd1.Timer','NextElapseUSecMonotonic')
 if not re.fullmatch(r't [0-9]+',value):raise RuntimeError('wake unavailable')
 wake=int(value[2:])*1000;now_mono=time.monotonic_ns();now_wall=time.time_ns()
 if now_wall<before_wall or abs((now_wall-before_wall)-(now_mono-before_mono))>1_000_000_000 or not now_mono<wake<=before_mono+(reviewed['expiry_ms']*1_000_000-before_wall):raise RuntimeError('deadline or clock uncertain')
 result={'schema':1,'target':g,'boot_id':reviewed['boot_id'],'binding_sha256':reviewed['binding_sha256'],'verified_grant_sha256':reviewed['verified_grant_sha256'],'wake_monotonic_ns':wake,'expiry_ms':reviewed['expiry_ms'],'engine_effects':False}
 deadline.store(STATE/(g+'.deadline-armed.json'),result)
 return result
