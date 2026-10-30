"""Review-only synthetic native deadline canary, not an entry point.

Execute only via reviewed source-pinned bridge that supplies the independently
pinned nuc_root_deadline_arm module as `deadline`; no model or Docker runs here.
Unknown or failed operations retain all owned state for exact recovery.
"""
import json,os,pathlib,time
ALPH='0123456789ABCDEFGHJKMNPQRSTVWXYZ'

def new_id():
 n=(int(time.time()*1000)<<80)|int.from_bytes(os.urandom(10),'big')
 return ''.join(ALPH[(n>>shift)&31] for shift in range(125,-1,-5))

def observe(pred,seconds):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if pred():return
  time.sleep(.05)
 raise RuntimeError('observation timed out; retain state')

def cleanup_transient(deadline,name):
 """Accept GC only for a known exact unit and an inactive manager state."""
 def properties():
  values={}
  for key in ('LoadState','ActiveState','Job','Names','Transient','FragmentPath','DropInPaths'):
   values[key]=deadline.property_value(name,key)
  return values
 p=properties()
 if p['LoadState']=='not-found':
  if p['ActiveState']!='inactive' or p['Job'] not in ('','0'):raise RuntimeError('absent unit state unresolved')
  return 'already_collected'
 if p['LoadState']!='loaded' or p['Names']!=name or p['Transient']!='yes' or p['FragmentPath']!='/run/systemd/transient/'+name or p['DropInPaths'] or p['Job'] not in ('','0'):raise RuntimeError('unit identity unresolved')
 deadline.run('/usr/bin/systemctl','stop',name)
 p=properties()
 if p['ActiveState']!='inactive' or p['Job'] not in ('','0'):raise RuntimeError('unit stop unresolved')
 if p['LoadState'] not in ('loaded','not-found') or (p['LoadState']=='loaded' and (p['Names']!=name or p['Transient']!='yes' or p['FragmentPath']!='/run/systemd/transient/'+name or p['DropInPaths'])):raise RuntimeError('post-stop identity unresolved')
 return 'stopped'

def native_deadline_canary(deadline):
 if os.geteuid()!=0:raise RuntimeError('root required')
 for directory in (deadline.ROOT,deadline.GRANTS,deadline.STATE):deadline.private_dir(directory)
 deadline.fixed_binary()
 target=new_id();task=new_id();sl='sfactory'+target.lower()+'.slice';unit='sfactory'+target.lower()+'-deadline-anchor.service';cg=pathlib.Path('/sys/fs/cgroup')/sl
 catalog=deadline.ROOT/(target+'.json');grant_path=deadline.GRANTS/(target+'.json')
 if cg.exists() or catalog.exists() or grant_path.exists():raise RuntimeError('fixture collision')
 if deadline.run('/usr/bin/systemctl','show',unit,'-p','LoadState','--value') not in ('','not-found'):raise RuntimeError('fixture unit collision')
 deadline.store(deadline.STATE/(target+'.deadline-canary-intent.json'),{'target':target,'unit':unit,'slice':sl,'purpose':'native-deadline-sleeper'})
 print('CANARY_TARGET '+target,flush=True)
 # Fixed, harmless task-owned processes. No model code, daemon, bind mounts or network.
 worker="import subprocess,time;subprocess.Popen(['/usr/bin/setsid','/usr/bin/sleep','60']);print('READY',flush=True);time.sleep(60)"
 deadline.run('/usr/bin/systemd-run','--unit='+unit,'--slice='+sl,'--property=User=sfgoose-worker','--property=PrivateNetwork=yes','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=RuntimeMaxSec=60s','/usr/bin/python3','-I','-B','-c',worker)
 try:
  observe(cg.exists,10);procs=cg/unit/'cgroup.procs';observe(procs.exists,10);observe(lambda:len(procs.read_text().splitlines())>=2,10)
  boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();st=cg.stat()
  deadline.store(catalog,{'schema':1,'target_id':target,'task_id':task,'generation':target,'boot_id':boot,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino})
  _,cat_hash=deadline.pinned_json(catalog);now=time.time_ns()
  deadline.store(grant_path,{'schema':1,'target_id':target,'boot_id':boot,'catalog_sha256':cat_hash,'issued_unix_ns':now,'expires_unix_ns':now+25_000_000_000,'max_duration_seconds':25,'purpose':'synthetic-canary-only'})
  spec=deadline.plan(target);result=deadline.arm(spec)
  if result['status']!='armed_not_admitted':raise RuntimeError('timer arm unresolved')
  # Positive control: two live native processes were observed immediately before arm.
  def stopped():
   event=dict(line.split() for line in (cg/'cgroup.events').read_text().splitlines())
   return cg.stat().st_ino==st.st_ino and event.get('frozen')=='1' and event.get('populated')=='0'
  observe(stopped,35)
  if not (deadline.STATE/(target+'.closed')).exists():raise RuntimeError('closure missing')
  desc=deadline.run('/usr/bin/systemctl','show',unit,'-p','ControlGroup','--value')
  if desc not in ('','/'+sl+'/'+unit) or any(p.name!=unit for p in cg.iterdir() if p.is_dir()):raise RuntimeError('unexpected child identity')
  deadline.run('/usr/bin/systemctl','stop',unit);deadline.run('/usr/bin/systemctl','stop',sl)
  if cg.exists():raise RuntimeError('slice removal unresolved')
  cleanup_transient(deadline,spec['timer']);cleanup_transient(deadline,spec['service'])
  deadline.store(deadline.STATE/(target+'.deadline-canary-receipt.json'),{'target':target,'slice':sl,'unit':unit,'timer':spec['timer'],'same_inode_frozen_empty':True,'engine_reconciled':False,'slice_removed':True})
  return {'target':target,'same_inode_frozen_empty':True,'engine_reconciled':False,'slice_removed':True}
 except Exception:
  print('RETAINED_UNKNOWN target='+target+' unit='+unit+' slice='+sl,flush=True)
  raise
