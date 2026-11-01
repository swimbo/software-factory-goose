"""Root-only fixed evaluator backend candidate; unregistered and not installed.

Catalog and snapshot provenance must be verified by the service bootstrap before
construction. All engine and manager operations use pinned installed helpers.
"""
import hashlib,json,os,pathlib,re,stat,subprocess,sys,time
from nuc_registry_eval_broker import Unavailable,canonical,durable
IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
HEX=re.compile(r'[0-9a-f]{64}\Z');ID=re.compile(r'[0-7][0-9A-HJKMNP-TV-Z]{25}\Z')
MAX=65536
class Backend:
 def __init__(self,rootfd,catalog,helper,deadline,snapshot):
  if os.geteuid()!=0 or not isinstance(catalog,dict) or set(catalog)!={'schema','generation','snapshot_sha256','challenges','boot_id'} or catalog['schema']!=1 or not ID.fullmatch(catalog['generation']) or len(catalog['challenges'])!=22 or not callable(snapshot):raise Unavailable('catalog unavailable')
  if set(catalog['snapshot_sha256'])!={'hello.py','test_hello.py'} or any(not isinstance(v,str) or not HEX.fullmatch(v) for v in catalog['snapshot_sha256'].values()):raise Unavailable('snapshot unavailable')
  ids=[x.get('target') for x in catalog['challenges'] if isinstance(x,dict)]
  if len(ids)!=22 or len(set(ids))!=22 or any(not isinstance(v,str) or not ID.fullmatch(v) for v in ids):raise Unavailable('targets unavailable')
  self.rootfd=rootfd;self.c=catalog;self.h=helper;self.deadline=deadline;self.snapshot=snapshot
 def record(self,seq,name,obj):durable(self.rootfd,f'{seq:02}.{name}',canonical(obj))
 def guard(self,target,st,wake):
  cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+target.lower()+'.slice');now=cg.stat();events=(cg/'cgroup.events').read_text().splitlines()
  if (now.st_dev,now.st_ino)!=(st.st_dev,st.st_ino) or events.count('frozen 0')!=1 or os.path.lexists(pathlib.Path('/var/lib/software-factory-goose/stop')/(target+'.closed')) or time.monotonic_ns()>=wake or self.deadline.base.property_value('sfactorydeadline'+target.lower()+'.timer','ActiveState')!='active':raise Unavailable('admission closed')
  self.h['engine_guard']()
 def launch_and_reconcile(self,q,intent_sha):
  self.stage='admission'
  try:return self._launch(q,intent_sha)
  except Exception:
   print('evaluator backend unavailable stage='+self.stage,file=sys.stderr,flush=True)
   raise
 def _launch(self,q,intent_sha):
  seq=q['sequence'];entry=self.c['challenges'][seq-1];target=entry['target'];h=self.h;d=self.deadline
  if set(entry)!={'target','task_id','cgroup_dev','cgroup_ino','snapshot_path','snapshot_dev','snapshot_ino','generation'} or entry['generation']!=self.c['generation'] or self.snapshot(entry)!=self.c['snapshot_sha256']:raise Unavailable('snapshot changed')
  cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+target.lower()+'.slice');st=cg.stat()
  if (st.st_dev,st.st_ino)!=(entry['cgroup_dev'],entry['cgroup_ino']) or (cg/'cgroup.events').read_text().splitlines().count('populated 0')!=1:raise Unavailable('cgroup unavailable')
  # The bootstrap installs a root-protected task record and scoped deadline
  # grant. arm() verifies both and fsyncs a timer intent before manager effects.
  self.stage='deadline'
  self.record(seq,'deadline-intent',{'target':target,'intent_sha256':intent_sha});armed=d.arm(d.plan(target));wake=armed['wake_monotonic_ns'];self.record(seq,'deadline-armed',{'target':target,'wake_monotonic_ns':wake})
  self.guard(target,st,wake)
  name='sfactoryeval'+target.lower();cmd=['-I','-B','/work/hello.py',*q['args']] if q['kind']=='hello' else ['-I','-B','-m','unittest','discover','-s','/work','-p','test_hello.py']
  args=h['DOCKER']+['create','--name',name,'--label','org.software-factory.evaluation='+target,'--cgroup-parent','sfactory'+target.lower()+'.slice','--network','none','--cgroupns','private','--ipc','private','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','32','--memory','128m','--cpus','0.5','--restart','no','--user','2001:2001','--pull','never','--log-driver','json-file','--log-opt','max-size=1m','--log-opt','max-file=2','--mount','type=bind,src='+entry['snapshot_path']+',dst=/work,readonly','--entrypoint','/usr/local/bin/python3',IMAGE,*cmd]
  self.stage='create'
  self.record(seq,'create-intent',{'target':target,'name':name});self.guard(target,st,wake)
  ident=h['fixed_run'](args,timeout=30).decode().strip()
  if not HEX.fullmatch(ident):raise Unavailable('create outcome unknown')
  self.record(seq,'created',{'target':target,'id':ident});self.guard(target,st,wake)
  self.inspect(entry,ident,name,'created',cmd)
  self.stage='start'
  self.record(seq,'start-intent',{'target':target,'id':ident});self.guard(target,st,wake)
  self.stage='attached_output'
  exit_code,out,err=self.capture_start(h,ident)
  self.guard(target,st,wake)
  self.stage='exit_receipt'
  self.record(seq,'exit-observed',{'target':target,'id':ident,'exit_code':exit_code})
  # Stop via the already armed, independent root unit before accepting output.
  self.stage='kernel_stop'
  d.run('/usr/bin/systemctl','start',armed['timer'].removesuffix('.timer')+'.service',timeout=15)
  end=time.monotonic()+15
  while time.monotonic()<end:
   e=(cg/'cgroup.events').read_text().splitlines()
   if e.count('frozen 1')==1 and e.count('populated 0')==1:break
   time.sleep(.1)
  else:raise Unavailable('kernel stop unknown')
  self.stage='stop_observation'
  state=pathlib.Path('/var/lib/software-factory-goose/stop')
  if h['rootfile'](state/(target+'.closed'))!=(target+'\n').encode():raise Unavailable('closure unavailable')
  observation=json.loads(h['rootfile'](state/(target+'.observation')))
  if observation.get('target_id')!=target or observation.get('boot_id')!=self.c['boot_id'] or (observation.get('cgroup_dev'),observation.get('cgroup_ino'))!=(st.st_dev,st.st_ino) or any(observation.get(k) is not True for k in ('observed','closed','frozen','empty')) or observation.get('engine_reconciled') is not False:raise Unavailable('stop observation unavailable')
  self.stage='exit_inspect'
  h['engine_guard']();terminal_deadline=time.monotonic()+10
  while True:
   try:observed=self.inspect(entry,ident,name,'exited',cmd);break
   except Exception:
    if time.monotonic()>=terminal_deadline:raise Unavailable('terminal status unavailable') from None
    time.sleep(.1)
  if type(observed.get('ExitCode')) is not int or observed['ExitCode']!=exit_code or observed.get('StartedAt') in (None,'','0001-01-01T00:00:00Z'):raise Unavailable('container exit unavailable')
  self.stage='remove'
  self.record(seq,'remove-intent',{'target':target,'id':ident});h['fixed_run'](h['DOCKER']+['rm',ident],timeout=15)
  p=subprocess.run(h['DOCKER']+['inspect',ident],env=h['ENV'],capture_output=True,timeout=10,check=False)
  if p.returncode==0 or len(p.stdout)>8192 or len(p.stderr)>8192 or b'no such object' not in p.stderr.lower():raise Unavailable('removal unknown')
  self.stage='post_remove'
  h['engine_guard']();now=cg.stat();e=(cg/'cgroup.events').read_text().splitlines()
  if (now.st_dev,now.st_ino)!=(st.st_dev,st.st_ino) or e.count('frozen 1')!=1 or e.count('populated 0')!=1 or self.snapshot(entry)!=self.c['snapshot_sha256']:raise Unavailable('cleanup unknown')
  self.record(seq,'removed',{'target':target,'id':ident,'frozen_empty':True})
  self.stage='timer_stop'
  d.run('/usr/bin/systemctl','stop',armed['timer'],timeout=15)
  return {'generation':self.c['generation'],'sequence':seq,'intent_sha256':intent_sha,'candidate_sha256':self.c['snapshot_sha256'],'container_id':ident,'deadline_armed':True,'kernel_empty':True,'exact_id_removed':True,'exit_code':exit_code,'stdout':out,'stderr':err}
 def inspect(self,entry,ident,name,status,cmd):
  h=self.h;objects=json.loads(h['fixed_run'](h['DOCKER']+['inspect',ident]));o=objects[0] if len(objects)==1 else {};c=o.get('Config',{});host=o.get('HostConfig',{});state=o.get('State',{});mounts=o.get('Mounts',[])
  if o.get('Id')!=ident or o.get('Name')!='/'+name or o.get('Image')!=IMAGE or state.get('Status')!=status or c.get('User')!='2001:2001' or c.get('Entrypoint')!=['/usr/local/bin/python3'] or c.get('Cmd')!=cmd or (c.get('Labels') or {}).get('org.software-factory.evaluation')!=entry['target'] or host.get('LogConfig')!={'Type':'json-file','Config':{'max-size':'1m','max-file':'2'}} or host.get('NetworkMode')!='none' or host.get('CgroupnsMode')!='private' or host.get('IpcMode')!='private' or host.get('SecurityOpt') not in (['no-new-privileges'],['no-new-privileges:true']) or host.get('RestartPolicy',{}).get('Name')!='no' or host.get('Binds') not in (None,[]) or host.get('Devices') not in (None,[]) or host.get('DeviceRequests') not in (None,[]) or host.get('CgroupParent')!='sfactory'+entry['target'].lower()+'.slice' or host.get('ReadonlyRootfs') is not True or host.get('Privileged') is not False or host.get('CapDrop')!=['ALL'] or host.get('CapAdd') not in (None,[]) or host.get('PidsLimit')!=32 or host.get('Memory')!=128*1024**2 or host.get('NanoCpus')!=500000000 or len(mounts)!=1 or mounts[0].get('Type')!='bind' or mounts[0].get('Source')!=entry['snapshot_path'] or mounts[0].get('Destination')!='/work' or mounts[0].get('RW') is not False:raise Unavailable('container identity unavailable')
  return state
 def capture_start(self,h,ident):
  import selectors
  # Attached pipes retain the complete stream. Rotating Docker logs cannot
  # establish that an earlier prefix was not lost.
  p=subprocess.Popen(h['DOCKER']+['start','-a',ident],env=h['ENV'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE);end=time.monotonic()+20;sel=selectors.DefaultSelector();out={}
  try:
   for name,fd in [('stdout',p.stdout),('stderr',p.stderr)]:os.set_blocking(fd.fileno(),False);sel.register(fd,selectors.EVENT_READ,name);out[name]=bytearray()
   while sel.get_map():
    remain=end-time.monotonic()
    if remain<=0:raise Unavailable('output unknown')
    for key,_ in sel.select(remain):
     b=os.read(key.fileobj.fileno(),4096)
     if not b:sel.unregister(key.fileobj);continue
     out[key.data].extend(b)
     if len(out[key.data])>MAX:raise Unavailable('output too large')
   code=p.wait(timeout=max(.01,end-time.monotonic()))
   if not 0<=code<=255:raise Unavailable('exit unavailable')
   return code,bytes(out['stdout']),bytes(out['stderr'])
  finally:
   sel.close()
   if p.poll() is None:p.kill();p.wait()
   p.stdout.close();p.stderr.close()

def verify_snapshot(entry,no_acl):
 """Check only the fixed root-owned snapshot path and its exact inode/files."""
 path=entry['snapshot_path'];generation=entry.get('generation')
 if not isinstance(generation,str) or not ID.fullmatch(generation) or path!='/var/lib/software-factory-goose/evaluator/'+generation+'/snapshot':raise Unavailable('snapshot path unavailable')
 parts=pathlib.Path(path).parts;fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for part in parts[1:]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=child
   st=os.fstat(fd);no_acl(fd,True)
   if st.st_uid!=0 or st.st_gid!=0 or st.st_mode&0o022:raise Unavailable('snapshot ancestor unavailable')
  st=os.fstat(fd)
  if (st.st_dev,st.st_ino,stat.S_IMODE(st.st_mode))!=(entry['snapshot_dev'],entry['snapshot_ino'],0o555) or set(os.listdir(fd))!={'hello.py','test_hello.py'}:raise Unavailable('snapshot unavailable')
  hashes={}
  for name in ('hello.py','test_hello.py'):
   child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
   try:
    st=os.fstat(child);no_acl(child,False)
    if not stat.S_ISREG(st.st_mode) or (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))!=(0,0,1,0o444) or st.st_size>8192:raise Unavailable('snapshot file unavailable')
    data=os.read(child,8193)
    if len(data)!=st.st_size:raise Unavailable('snapshot changed')
    hashes[name]=hashlib.sha256(data).hexdigest()
   finally:os.close(child)
  return hashes
 finally:os.close(fd)
