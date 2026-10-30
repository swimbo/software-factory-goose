"""Review-only fixed synthetic Docker + root launch + deadline canary.

The bridge must pin and inject the reviewed deadline and native-canary modules.
Never import mutable host code as root. Unknown outcomes retain all state and
resources; this source has not been run. No production grant/model/provider.
"""
import hashlib,json,os,pathlib,stat,subprocess,time
CANDIDATE=pathlib.Path('/tmp/sfactory-stop-build-_10otcq2/install-candidate/sfactory_synthetic_docker_launch_v2')
SHA='e5406f51749073fd7e1e59ae96ed818d53e203d2424a3085867b6eaa0bcad913'
D=['/usr/bin/docker','--host','unix:///run/docker.sock']
ORIGINAL='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062'

def root_record(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>4096:raise RuntimeError('untrusted launch record')
  b=f.read(4097)
  if len(b)!=s.st_size or f.read(1):raise RuntimeError('launch record changed')
  return b

def guard(deadline):
 info=deadline.run(*D,'info','--format','{{.ID}}');commit=deadline.run(*D,'version','--format','{{.Server.GitCommit}}');version=deadline.run(*D,'version','--format','{{.Server.Version}}');pid=deadline.run('/usr/bin/systemctl','show','docker.service','-p','MainPID','--value')
 objects=json.loads(deadline.run(*D,'inspect',ORIGINAL))
 if len(objects)!=1:raise RuntimeError('original guard ambiguous')
 o=objects[0]
 if info!='56d25a60-5f64-4212-b904-e750067ac6a5' or commit!='3ce5872' or version!='29.8.0' or pid!='2145' or o['Id']!=ORIGINAL or o['Name']!='/sf-owner-224a71d2db764249aa6cade3c1b39c80' or o['State']['Status']!='created' or o['State']['Pid']!=0 or (o['Config']['Labels'] or {}).get('org.software-factory.escape-spike')!='224a71d2db764249aa6cade3c1b39c80':raise RuntimeError('daemon or original guard changed')

def owned_object(deadline,target,ident):
 a=json.loads(deadline.run(*D,'inspect',ident))
 if len(a)!=1:raise RuntimeError('container inspection ambiguous')
 o=a[0];h=o['HostConfig']
 if o['Id']!=ident or o['Name']!='/sfactory-launch-'+target.lower() or (o['Config']['Labels'] or {}).get('org.software-factory.root-launch-canary')!=target or h['CgroupParent']!='sfactory'+target.lower()+'.slice' or o['Image']!='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937':raise RuntimeError('owned container identity changed')
 return o

def copy_candidate(deadline,target):
 fd=os.open(CANDIDATE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=1000 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o700 or s.st_size>64*1024*1024:raise RuntimeError('candidate metadata')
  data=f.read(64*1024*1024+1)
  if len(data)!=s.st_size or hashlib.sha256(data).hexdigest()!=SHA:raise RuntimeError('candidate digest')
 dest=deadline.STATE/(target+'.synthetic-launcher')
 fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o700)
 with os.fdopen(fd,'wb') as f:
  os.fchmod(f.fileno(),0o700);st=os.fstat(f.fileno())
  if st.st_uid!=0 or st.st_gid!=0:raise RuntimeError('launcher owner')
  f.write(data);f.flush();os.fsync(f.fileno())
 fd=os.open(deadline.STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 return dest

def synthetic_docker_deadline_canary(deadline,native):
 if os.geteuid()!=0:raise RuntimeError('root required')
 for d in (deadline.ROOT,deadline.GRANTS,deadline.STATE):deadline.private_dir(d)
 deadline.fixed_binary();guard(deadline)
 g=native.new_id();task=native.new_id();sl='sfactory'+g.lower()+'.slice';anchor='sfactory'+g.lower()+'-docker-anchor.service';cg=pathlib.Path('/sys/fs/cgroup')/sl
 if cg.exists() or os.path.lexists(deadline.ROOT/(g+'.json')) or os.path.lexists(deadline.GRANTS/(g+'.json')):raise RuntimeError('fixture collision')
 if deadline.run('/usr/bin/systemctl','show',anchor,'-p','LoadState','--value') not in ('','not-found'):raise RuntimeError('anchor collision')
 deadline.store(deadline.STATE/(g+'.docker-canary-intent.json'),{'target':g,'slice':sl,'unit':anchor,'purpose':'synthetic-root-launch-deadline','launcher_sha256':SHA})
 print('CANARY_TARGET '+g,flush=True)
 launcher=copy_candidate(deadline,g)
 # The anchor pins the task-owned cgroup before the root catalogue is minted.
 deadline.run('/usr/bin/systemd-run','--unit='+anchor,'--slice='+sl,'--property=User=sfgoose-worker','--property=PrivateNetwork=yes','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=RuntimeMaxSec=60s','/usr/bin/sleep','60')
 try:
  native.observe(cg.exists,10);st=cg.stat();boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  deadline.store(deadline.ROOT/(g+'.json'),{'schema':1,'target_id':g,'task_id':task,'generation':g,'boot_id':boot,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino})
  _,catsha=deadline.pinned_json(deadline.ROOT/(g+'.json'));now=time.time_ns()
  deadline.store(deadline.GRANTS/(g+'.json'),{'schema':1,'target_id':g,'boot_id':boot,'catalog_sha256':catsha,'issued_unix_ns':now,'expires_unix_ns':now+25_000_000_000,'max_duration_seconds':25,'purpose':'synthetic-canary-only'})
  spec=deadline.plan(g);deadline.arm(spec)
  guard(deadline)
  # Timeout is unknown: the launch transaction's durable create intent/seal own recovery.
  out=deadline.run(str(launcher),g,timeout=15);result=json.loads(out);ident=result.get('id','')
  if result.get('target')!=g or len(ident)!=64 or any(c not in '0123456789abcdef' for c in ident):raise RuntimeError('launcher result unknown')
  _,grantsha=deadline.pinned_json(deadline.GRANTS/(g+'.json'))
  binding=hashlib.sha256(b'sfactory-synthetic-launch-v1\0'+catsha.encode()+grantsha.encode()+b'synthetic-network-none-python311-shell-setsid-sleep60-v1').hexdigest()
  for suffix,expected in (('launch-consumed',f'{g}\n{binding}\n'),('create-intent',f'{g}\n{binding}\n'),('launch-seal',f'{g}\n{binding}\n{ident}\n'),('start-intent',f'{g}\n{binding}\n{ident}\n')):
   if root_record(deadline.STATE/(g+'.'+suffix))!=expected.encode():raise RuntimeError('durable launch record mismatch')
  o=owned_object(deadline,g,ident)
  if o['State']['Status']!='running' or o['State']['Pid']<=0:raise RuntimeError('positive running control missing')
  scope=cg/('docker-'+ident+'.scope')/'cgroup.procs'
  native.observe(scope.exists,5);native.observe(lambda:len(scope.read_text().splitlines())>=2,5)
  pids=[int(v) for v in scope.read_text().splitlines()]
  if o['State']['Pid'] not in pids or not any(p!=o['State']['Pid'] and os.getsid(p)==p for p in pids):raise RuntimeError('setsid descendant not observed')
  # Actual kernel evidence that this pinned worker is under seccomp, not only config.
  status=pathlib.Path('/proc')/str(o['State']['Pid'])/'status'
  fields=dict(line.split(':',1) for line in status.read_text().splitlines() if ':' in line)
  if fields.get('Seccomp','').strip()!='2' or fields.get('NoNewPrivs','').strip()!='1' or fields.get('CapEff','').strip()!='0000000000000000' or fields.get('Uid','').split()!=['2001']*4:raise RuntimeError('worker kernel restrictions not observed')
  def stopped():
   ev=dict(line.split() for line in (cg/'cgroup.events').read_text().splitlines())
   return cg.stat().st_ino==st.st_ino and ev.get('frozen')=='1' and ev.get('populated')=='0'
  native.observe(stopped,35)
  if root_record(deadline.STATE/(g+'.closed'))!=(g+'\n').encode():raise RuntimeError('closure missing')
  guard(deadline);o=owned_object(deadline,g,ident)
  if o['State']['Running'] or o['State']['Pid']!=0:raise RuntimeError('owned container still running')
  # A successful exact full-ID non-force removal closes this known start outcome.
  deadline.run(*D,'rm',ident)
  p=subprocess.run(D+['inspect',ident],capture_output=True,text=True,timeout=10,env=deadline.ENV)
  if p.returncode==0 or 'no such object' not in p.stderr.lower():raise RuntimeError('removal unresolved')
  if cg.stat().st_ino!=st.st_ino or dict(x.split() for x in (cg/'cgroup.events').read_text().splitlines()).get('populated')!='0':raise RuntimeError('post-removal cgroup uncertain')
  guard(deadline)
  if any(p.name not in (anchor,'docker-'+ident+'.scope') for p in cg.iterdir() if p.is_dir()):raise RuntimeError('unexpected cgroup child')
  deadline.run('/usr/bin/systemctl','stop',anchor);deadline.run('/usr/bin/systemctl','stop',sl)
  if cg.exists():raise RuntimeError('slice removal unresolved')
  native.cleanup_transient(deadline,spec['timer']);native.cleanup_transient(deadline,spec['service'])
  deadline.store(deadline.STATE/(g+'.docker-canary-receipt.json'),{'target':g,'container_id':ident,'slice':sl,'unit':anchor,'launcher_sha256':SHA,'positive_two_container_processes':True,'setsid_descendant_observed':True,'worker_seccomp_mode':2,'same_inode_frozen_empty':True,'exact_container_removed':True,'slice_removed':True,'engine_reconciled_for_fixture':True})
  return {'target':g,'container_id':ident,'fixture_passed':True,'engine_reconciled_for_fixture':True}
 except Exception:
  print('RETAINED_UNKNOWN target='+g+' slice='+sl+' unit='+anchor,flush=True);raise

NEGATIVE_CANDIDATE=pathlib.Path('/tmp/sfactory-stop-build-_10otcq2/install-candidate/sfactory_synthetic_inspect_negative')
NEGATIVE_SHA='358e49ff594e537a84a70e9d8d3b968a31a79ed1a4c2684705902b895090f91c'

def negative_controls(deadline,native):
 """Created-only negatives. No start. Each mutation has its own durable intent."""
 guard(deadline)
 fd=os.open(NEGATIVE_CANDIDATE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=1000 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o700 or s.st_size>64*1024*1024:raise RuntimeError('negative verifier metadata')
  data=f.read(64*1024*1024+1)
  if len(data)!=s.st_size or hashlib.sha256(data).hexdigest()!=NEGATIVE_SHA:raise RuntimeError('negative verifier digest')
 batch=native.new_id();dest=deadline.STATE/(batch+'.synthetic-negative-verifier')
 deadline.store(deadline.STATE/(batch+'.negative-batch-intent.json'),{'batch':batch,'verifier_sha256':NEGATIVE_SHA,'purpose':'created-only-negative-config'})
 fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o700)
 with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o700);f.write(data);f.flush();os.fsync(f.fileno())
 fd=os.open(deadline.STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 results=[]
 for kind in ('recipe','parent'):
  g=native.new_id();name='sfactory-launch-'+g.lower();expected='sfactory'+g.lower()+'.slice';parent=expected if kind=='recipe' else 'sfactory'+native.new_id().lower()+'.slice';program='true' if kind=='recipe' else '/usr/bin/setsid /bin/sleep 60 & wait'
  deadline.store(deadline.STATE/(g+'.negative-intent.json'),{'target':g,'batch':batch,'name':name,'kind':kind,'cgroup_parent':parent,'created_only':True})
  guard(deadline)
  ident=deadline.run(*D,'create','--name',name,'--label','org.software-factory.root-launch-canary='+g,'--cgroup-parent',parent,'--network','none','--cgroupns','private','--ipc','private','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','16','--memory','128m','--cpus','0.5','--restart','no','--user','2001:2001','--pull','never','--entrypoint','/bin/sh','sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937','-c',program)
  if len(ident)!=64 or any(c not in '0123456789abcdef' for c in ident):raise RuntimeError('negative create unresolved')
  deadline.store(deadline.STATE/(g+'.negative-created.json'),{'target':g,'batch':batch,'kind':kind,'id':ident})
  objects=json.loads(deadline.run(*D,'inspect',ident))
  if len(objects)!=1:raise RuntimeError('negative inspect ambiguous')
  o=objects[0]
  if o['Id']!=ident or o['Name']!='/'+name or o['State']['Status']!='created' or o['State']['Pid']!=0 or (o['Config']['Labels'] or {}).get('org.software-factory.root-launch-canary')!=g or o['Image']!='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937' or o['Config']['Cmd']!=['-c',program] or o['HostConfig']['CgroupParent']!=parent:raise RuntimeError('negative identity mismatch')
  if deadline.run(str(dest),g,ident)!='EXPECTED_CONFIG_REFUSAL':raise RuntimeError('negative refusal unavailable')
  guard(deadline)
  # Recheck exact object and no start immediately before the sole removal attempt.
  objects=json.loads(deadline.run(*D,'inspect',ident));o=objects[0] if len(objects)==1 else {}
  if o.get('Id')!=ident or o.get('Name')!='/'+name or o.get('State',{}).get('Status')!='created' or o.get('State',{}).get('Pid')!=0 or (o.get('Config',{}).get('Labels') or {}).get('org.software-factory.root-launch-canary')!=g:raise RuntimeError('negative cleanup identity mismatch')
  deadline.run(*D,'rm',ident)
  p=subprocess.run(D+['inspect',ident],capture_output=True,text=True,timeout=10,env=deadline.ENV)
  if p.returncode==0 or 'no such object' not in p.stderr.lower():raise RuntimeError('negative removal unresolved')
  guard(deadline)
  deadline.store(deadline.STATE/(g+'.negative-receipt.json'),{'target':g,'batch':batch,'kind':kind,'id':ident,'configuration_refused':True,'never_started':True,'exact_id_removed':True})
  results.append({'target':g,'kind':kind,'id':ident})
 return {'batch':batch,'controls':results}
