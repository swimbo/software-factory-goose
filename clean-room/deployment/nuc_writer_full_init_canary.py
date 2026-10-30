"""Synthetic writer-init fixture construction; no live authority or entrypoint yet.

Host orchestration must arm an independent deadline and prove exact teardown
before executing this candidate. Synthetic records never enter the journal.
"""
import hashlib,json,re
G='01M65RMR3F04YB1B016EBBSXGJ';TASK='01M65RMR3FE6FQTFRBHERRHXSH'
HEX=re.compile(r'[0-9a-f]{64}\Z')
MODELS=['deepseek-v4-pro:0813','deepseek-v4.1-flash:1017','ollama-cloud/deepseek-v4-pro:0813','ollama-cloud/deepseek-v4.1-flash:1017']
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(x):return hashlib.sha256(x).hexdigest()
def build(provider,writer,dirs,boot,dev,ino,expiry_ms,wake_ns):
 if not isinstance(provider,dict) or set(provider)!={'schema','container_id','image_id','pid','network_device','network_inode','sandbox_key','port'} or provider['schema']!=1 or not HEX.fullmatch(provider['container_id']) or not re.fullmatch(r'sha256:[0-9a-f]{64}',provider['image_id']) or provider['port']!=8080:raise ValueError('provider binding')
 if not isinstance(writer,dict) or set(writer)!={'id','image','program'} or any(not isinstance(writer[k],str) or not HEX.fullmatch(writer[k]) for k in writer):raise ValueError('writer binding')
 if set(dirs)!={'input_dir','output_dir','candidate_dir'} or any(not isinstance(dirs[k],dict) or set(dirs[k])!={'path','dev','ino'} or dirs[k]['path']!='/var/lib/software-factory-goose/handoff/'+G+'/'+k.removesuffix('_dir') or type(dirs[k]['dev']) is not int or type(dirs[k]['ino']) is not int or min(dirs[k]['dev'],dirs[k]['ino'])<=0 for k in dirs):raise ValueError('directories')
 if not isinstance(boot,str) or not re.fullmatch(r'[0-9a-f-]{36}',boot) or any(type(n) is not int or n<=0 for n in (dev,ino,expiry_ms,wake_ns)):raise ValueError('deadline')
 task={'schema':1,'target_id':G,'task_id':TASK,'generation':G,'boot_id':boot,'cgroup_dev':dev,'cgroup_ino':ino}
 catalog={'schema':1,'purpose':'synthetic-writer-init-canary','scope':{'generation':G},'generation':G,'task_id':TASK,'boot_id':boot};binding=sha(canonical(catalog)+b' synthetic-only')
 scope={'schema':2,'request_contract':'goose-turn-context-v1','generation':G,'task_id':TASK,'grant_sha256':binding,'catalog_sha256':sha(canonical(catalog)),'request_sha256':'0'*64,'allowed_models':MODELS,'provider_binding_sha256':sha(canonical(provider))}
 grant={'schema':1,'generation':G,'binding_sha256':binding,'reservation':{'generation':G,'scope':{'generation':G,'task_id':TASK},'expires_at_ms':expiry_ms,'hard_deadline_ms':expiry_ms}}
 armed={'schema':1,'target':G,'boot_id':boot,'binding_sha256':binding,'verified_grant_sha256':sha(canonical(grant)),'wake_monotonic_ns':wake_ns,'expiry_ms':expiry_ms,'engine_effects':False}
 mounts=sorted([{'source':dirs['candidate_dir']['path'],'destination':'/candidate','rw':True},{'source':dirs['input_dir']['path'],'destination':'/handoff/input','rw':False},{'source':dirs['output_dir']['path'],'destination':'/handoff/output','rw':True}],key=lambda x:x['destination'])
 seal={'schema':1,'purpose':'nuc-fixed-file-writer-v1','generation':G,'task_id':TASK,'binding_sha256':binding,'boot_id':boot,'writer_container_id':writer['id'],'writer_image_sha256':writer['image'],'writer_program_sha256':writer['program'],'cgroup_dev':dev,'cgroup_ino':ino,**dirs,'mounts_sha256':sha(canonical(mounts))}
 return {'task':task,'catalog':catalog,'scope':scope,'provider':provider,'consumed':(G+'\n'+binding+'\n').encode(),'grant':grant,'armed':armed,'writer':seal}

# This source is intentionally not executable until a reviewed orchestrator
# installs a separately supervised timer and exact owned-container cleanup. The
# synthetic constructor above must never be substituted for a journal grant.

# The host runner is deliberately supplied the separately pinned installed helper
# and deadline module by a reviewed wrapper. No caller-supplied path or command.
def plan_host(old,h,deadline,provider,images):
 import os,pathlib
 if os.geteuid()!=0:raise RuntimeError('root required')
 state=pathlib.Path('/var/lib/software-factory-goose/stop');root=old.ETC;run=old.RUN;handoff=pathlib.Path('/var/lib/software-factory-goose/handoff')/G
 names=('sfactorywriter'+G.lower()+'.socket','sfactorywriter'+G.lower()+'.service','sfactory'+G.lower()+'.slice')
 paths=[state/(G+'.full-init-intent.json'),state/(G+'.full-init-complete.json'),root/'tasks'/(G+'.json'),root/'launch-catalog'/(G+'.json'),*[root/'relay-catalog'/(G+'.'+x) for x in ('scope.json','provider.json','writer.json')],handoff,run/'writer'/(G+'.sock')]+[old.UNIT/n for n in names]
 if any(os.path.lexists(p) for p in paths) or any(p.name.startswith(G+'.') for p in state.iterdir()):raise RuntimeError('fixture state occupied')
 for n in (*names[:2],'sfactorydeadline'+G.lower()+'.timer','sfactorydeadline'+G.lower()+'.service','sfactory-writer-full-init-client-'+G.lower()+'.service'):
  if old.ctl('show',n,'-p','LoadState','--value')!='not-found':raise RuntimeError('fixture unit occupied')
  for parent in ('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system'):
   for path in (pathlib.Path(parent)/n,pathlib.Path(parent)/(n+'.d'),pathlib.Path(parent)/(n.rsplit('.',1)[1]+'.d')):
    if os.path.lexists(path):raise RuntimeError('unit alias or drop-in occupied')
 if (pathlib.Path('/sys/fs/cgroup')/names[2]).exists():raise RuntimeError('fixture slice occupied')
 h['engine_guard']();deadline.fixed_binary()
 for selector in ('label=org.software-factory.generation='+G,'name=^/sfactorywriter'+G.lower()+'$'):
  if h['fixed_run'](h['DOCKER']+['ps','-a','--filter',selector,'--format','{{.ID}}']).strip():raise RuntimeError('fixture Docker identity occupied')
 if not isinstance(provider,dict) or not isinstance(images,dict):raise RuntimeError('fixed inputs unavailable')
 return {'generation':G,'task':TASK,'provider':provider,'images':images,'units':list(names),'scope':'synthetic writer guard only; no real grant, key or provider HTTP'}

def apply_host(approved,old,h,deadline,prep,provider,images):
 import json,os,pathlib,re,subprocess,time
 if plan_host(old,h,deadline,provider,images)!=approved:raise RuntimeError('reviewed plan changed')
 state=pathlib.Path('/var/lib/software-factory-goose/stop');root=old.ETC;handoff=pathlib.Path('/var/lib/software-factory-goose/handoff')/G
 stopcat=root/'tasks'/(G+'.json');launch=root/'launch-catalog'/(G+'.json');prefix=root/'relay-catalog'/G
 slice_name='sfactory'+G.lower()+'.slice';anchor='sfactory'+G.lower()+'-full-init-anchor.service';timer='sfactorydeadline'+G.lower()+'.timer';timer_service='sfactorydeadline'+G.lower()+'.service'
 old.store(state/(G+'.full-init-intent.json'),canonical(approved),0o600)
 prep.G=G;prep.TASK=TASK;prep.LOW=G.lower();units=prep.units();names=approved['units']
 for n in names:old.store(old.UNIT/n,units[n],0o644)
 old.ctl('daemon-reload')
 for n in names:
  if old.ctl('show',n,'-p','FragmentPath','--value')!=str(old.UNIT/n) or old.ctl('show',n,'-p','DropInPaths','--value')!='':raise RuntimeError('unit identity unavailable')
 old.ctl('start',slice_name);cg=pathlib.Path('/sys/fs/cgroup')/slice_name;st=os.stat(cg)
 if st.st_uid!=0 or (cg/'cgroup.events').read_text().splitlines().count('populated 0')!=1:raise RuntimeError('fixture slice unavailable')
 for path,uid,gid,mode in [(handoff,0,0,0o700),(handoff/'input',0,0,0o755),(handoff/'output',2001,2001,0o755),(handoff/'candidate',2001,2001,0o755)]:
  os.mkdir(path,mode);os.chmod(path,mode)
  if uid:os.chown(path,uid,gid)
  old.syncdir(path.parent)
 dirs={}
 for name in ('input','output','candidate'):
  s=os.stat(handoff/name);dirs[name+'_dir']={'path':str(handoff/name),'dev':s.st_dev,'ino':s.st_ino}
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();expiry=time.time_ns()//1_000_000+210000
 writer={'id':'0'*64,'image':images['writer']['image_id'][7:],'program':images['writer']['program_sha256']}
 base=build(provider,writer,dirs,boot,st.st_dev,st.st_ino,expiry,1)
 old.store(stopcat,canonical(base['task']),0o600);old.store(launch,canonical(base['catalog']),0o600)
 old.store(state/(G+'.full-init-timer-intent.json'),canonical({'generation':G,'timer':timer,'service':timer_service}),0o600)
 deadline.run('/usr/bin/systemd-run','--unit='+timer_service[:-8],'--on-active=180s','--timer-property=AccuracySec=1ms','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=RestrictAddressFamilies=AF_UNIX','--property=MemoryMax=128M','--property=TasksMax=16','--property=CPUQuota=50%','--property=ReadWritePaths=/var/lib/software-factory-goose/stop /sys/fs/cgroup','--property=TimeoutStartSec=12s','--property=Restart=on-failure','--property=RestartSec=1s','--property=StartLimitIntervalSec=0',str(deadline.BINARY),G)
 deadline.verify_units({'target':G,'timer':timer,'service':timer_service})
 if deadline.property_value(timer,'ActiveState')!='active':raise RuntimeError('deadline timer unavailable')
 value=deadline.run('/usr/bin/busctl','get-property','org.freedesktop.systemd1',deadline.unit_path(timer),'org.freedesktop.systemd1.Timer','NextElapseUSecMonotonic')
 if not re.fullmatch(r't [0-9]+',value):raise RuntimeError('deadline wake unavailable')
 wake=int(value[2:])*1000
 current_mono=time.monotonic_ns();current_wall=time.time_ns()//1_000_000
 if not current_mono<wake<=current_mono+(expiry-current_wall)*1_000_000 or current_wall+1000>=expiry:raise RuntimeError('deadline unavailable')
 records=build(provider,writer,dirs,boot,st.st_dev,st.st_ino,expiry,wake)
 for suffix,key in [('grant-verified','grant'),('deadline-armed.json','armed')]:old.store(state/(G+'.'+suffix),canonical(records[key]),0o600)
 for suffix,key in [('scope.json','scope'),('provider.json','provider')]:old.store(pathlib.Path(str(prefix)+'.'+suffix),canonical(records[key]),0o600)
 old.store(state/(G+'.launch-consumed'),records['consumed'],0o600)
 def live_guard():
  if os.path.lexists(state/(G+'.closed')) or time.monotonic_ns()>=wake or time.time_ns()//1_000_000>=expiry or deadline.property_value(timer,'ActiveState')!='active' or (cg.stat().st_dev,cg.stat().st_ino)!=(st.st_dev,st.st_ino) or (cg/'cgroup.events').read_text().splitlines().count('frozen 0')!=1:raise RuntimeError('synthetic deadline closed')
  h['engine_guard']()
 live_guard();old.store(state/(G+'.writer-create-intent.json'),canonical({'generation':G,'role':'writer','synthetic':True}),0o600)
 live_guard();ident=h['fixed_run'](h['docker_args'](G,'writer'),timeout=30).decode().strip()
 if not HEX.fullmatch(ident):raise RuntimeError('writer create outcome unknown')
 old.store(state/(G+'.writer-created.json'),canonical({'generation':G,'id':ident}),0o600);live_guard();h['inspect'](G,'writer',ident,'created')
 writer['id']=ident;records=build(provider,writer,dirs,boot,st.st_dev,st.st_ino,expiry,wake);old.store(pathlib.Path(str(prefix)+'.writer.json'),canonical(records['writer']),0o600)
 old.store(state/(G+'.writer-start-intent.json'),canonical({'generation':G,'id':ident}),0o600);live_guard();h['fixed_run'](h['DOCKER']+['start',ident],timeout=15);live_guard();h['inspect'](G,'writer',ident,'running')
 live_guard();old.ctl('start',names[0]);live_guard();old.ctl('start',names[1]);live_guard()
 if old.ctl('show',names[1],'-p','ActiveState','--value')!='active' or int(old.ctl('show',names[1],'-p','MainPID','--value'))<=1:raise RuntimeError('writer broker unavailable')
 code="""import json,socket\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(30);s.connect(%r);s.sendall(b'{\"op\":\"guard\"}\\n');b=b''\nwhile not b.endswith(b'\\n') and len(b)<4097:\n c=s.recv(4097-len(b))\n if not c:break\n b+=c\nr=json.loads(b)
if r.get('open') is not True or r.get('generation')!=%r:raise RuntimeError('guard denied')
print('guard_passed')\n"""%(str(old.RUN/'writer'/(G+'.sock')),G)
 client='sfactory-writer-full-init-client-'+G.lower()+'.service'
 old.store(state/(G+'.guard-client-intent.json'),canonical({'unit':client}),0o600)
 p=subprocess.run(['/usr/bin/systemd-run','--unit='+client,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=40s','/usr/bin/python3','-I','-B','-c',code],env=old.ENV,capture_output=True,timeout=45,check=False)
 if p.returncode!=0 or p.stdout!=b'guard_passed\n' or len(p.stderr)>8192:raise RuntimeError('guard outcome unknown')
 old.store(state/(G+'.full-init-guard-passed.json'),canonical({'generation':G,'writer_id':ident}),0o600)
 old.ctl('start',timer_service)
 until=time.monotonic()+20
 while time.monotonic()<until:
  event=(cg/'cgroup.events').read_text().splitlines()
  if event.count('frozen 1')==1 and event.count('populated 0')==1:break
  time.sleep(.1)
 else:raise RuntimeError('kernel stop unresolved')
 if (cg.stat().st_dev,cg.stat().st_ino)!=(st.st_dev,st.st_ino):raise RuntimeError('cgroup identity changed')
 old.ctl('stop',names[0]);old.ctl('stop',names[1])
 if old.ctl('show',names[0],'-p','ActiveState','--value')!='inactive' or old.ctl('show',names[0],'-p','Job','--value')!='' or old.ctl('show',names[1],'-p','MainPID','--value')!='0' or old.ctl('show',names[1],'-p','ActiveState','--value') not in ('inactive','failed') or old.ctl('show',names[1],'-p','Job','--value')!='':raise RuntimeError('broker stop unresolved')
 h['engine_guard']();until=time.monotonic()+10
 while True:
  try:h['inspect'](G,'writer',ident,'exited');break
  except Exception:
   if time.monotonic()>=until:raise RuntimeError('writer terminal status unresolved') from None
   time.sleep(.1)
 old.store(state/(G+'.writer-remove-intent.json'),canonical({'id':ident}),0o600);h['fixed_run'](h['DOCKER']+['rm',ident],timeout=15)
 p=subprocess.run(h['DOCKER']+['inspect',ident],env=old.ENV,capture_output=True,timeout=10,check=False)
 events=(cg/'cgroup.events').read_text().splitlines();current=cg.stat()
 if p.returncode==0 or len(p.stdout)>8192 or len(p.stderr)>8192 or b'no such object' not in p.stderr.lower() or (current.st_dev,current.st_ino)!=(st.st_dev,st.st_ino) or events.count('populated 0')!=1 or events.count('frozen 1')!=1:raise RuntimeError('writer removal unresolved')
 h['engine_guard']()
 if old.ctl('show',names[0],'-p','ActiveState','--value')!='inactive' or old.ctl('show',names[0],'-p','Job','--value')!='' or old.ctl('show',names[1],'-p','MainPID','--value')!='0' or old.ctl('show',names[1],'-p','Job','--value')!='':raise RuntimeError('broker changed after removal')
 old.ctl('stop',timer);result={'generation':G,'writer_id':ident,'guard_passed':True,'frozen_empty':True,'exact_id_removed':True,'provider_http':False,'grant_requested':False};old.store(state/(G+'.full-init-complete.json'),canonical(result),0o600);return result
