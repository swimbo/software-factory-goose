"""Fixed exact-target deadline canary reconciliation; no systemd mutations.

Read-only PLAN checks the inventoried evidence; APPLY writes only one create-only
root-owned receipt. No process, unit, cgroup, timer, grant or catalogue is changed.
"""
import hashlib,json,os,pathlib,stat,subprocess
TARGET='01M65J0JBJN1CAS5SVTXZTEPZG'
BOOT='98b86bb5-c04c-46f5-951d-22e497102f29'
STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
ROOT=pathlib.Path('/etc/software-factory-goose/tasks')
GRANTS=pathlib.Path('/etc/software-factory-goose/deadline-grants')
CGROUP=pathlib.Path('/sys/fs/cgroup')
LOWER=TARGET.lower();SLICE='sfactory'+LOWER+'.slice';ANCHOR='sfactory'+LOWER+'-deadline-anchor.service';TIMER='sfactorydeadline'+LOWER+'.timer';SERVICE='sfactorydeadline'+LOWER+'.service'
RECEIPT=STATE/(TARGET+'.deadline-reconciled.json')
FILES={
 'intent':(STATE/(TARGET+'.deadline-canary-intent.json'),'cff110fe8047622e7e1a40e3230fbaa28e803e1e92bcb00fbc6f14e42583b3fe'),
 'catalog':(ROOT/(TARGET+'.json'),'95e6be62bc35b78706bb9feb63e415a88dc7dd91ad4d1ce278d9677cc8327a0b'),
 'grant':(GRANTS/(TARGET+'.json'),'4fafed249d64763bc6eff2bf1a4ae70235e98bfb3265f4dec947919cb7a1f466'),
 'arm_intent':(STATE/(TARGET+'.deadline-intent.json'),'5c72f1c9efb3b0e456470075e08b452003a8e96f2b89cd57eb0a1a20c61dcff3'),
 'armed':(STATE/(TARGET+'.deadline-armed.json'),'e3e89d0076fc558a83e2f9b4dfbd4d652914720567dfeec65efef22c8866431b'),
 'observation':(STATE/(TARGET+'.observation'),'f8fe15b0a2331fc5060c867f2feb30dea520f624f702da19da4373b572fadba8'),
 'closed':(STATE/(TARGET+'.closed'),'e06c5bfb54e2de74fdb134747818b45fc4d80433f63b2ca655710efd554d7781')}
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0','LC_ALL':'C'}
class Host:
 def __init__(self,source_digest=None):self.source_digest=source_digest

def read(path,sha):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>16384:raise RuntimeError('record metadata mismatch')
  b=f.read(16385)
  if len(b)!=s.st_size or f.read(1) or hashlib.sha256(b).hexdigest()!=sha:raise RuntimeError('record content mismatch')
 return b

def unit(name):
 p=subprocess.run(['/usr/bin/systemctl','show',name,'--property=LoadState,ActiveState,SubState,Job,Names,FragmentPath,DropInPaths,Transient,Result','--no-pager'],capture_output=True,text=True,timeout=10,env=ENV)
 if p.returncode or len(p.stdout)>16384:raise RuntimeError('manager unavailable')
 out={}
 for line in p.stdout.splitlines():
  k,sep,v=line.partition('=')
  if not sep or k in out:raise RuntimeError('manager result ambiguous')
  out[k]=v
 return out

def make_plan(host):
 if os.geteuid()!=0 or pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=BOOT:raise RuntimeError('boot/identity mismatch')
 for directory in (STATE,ROOT,GRANTS):
  for p in (directory,*directory.parents):
   s=p.lstat()
   if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_mode&0o022:raise RuntimeError('untrusted directory')
 if os.path.lexists(RECEIPT) or os.path.lexists(STATE/(TARGET+'.deadline-canary-receipt.json')):raise RuntimeError('receipt collision')
 raw={name:read(path,sha) for name,(path,sha) in FILES.items()}
 if raw['closed']!=(TARGET+'\n').encode():raise RuntimeError('closure mismatch')
 r={name:json.loads(value) for name,value in raw.items() if name!='closed'}
 cat=r['catalog'];grant=r['grant'];ob=r['observation'];intent=r['intent'];arm=r['arm_intent'];armed=r['armed']
 if intent!={'target':TARGET,'unit':ANCHOR,'slice':SLICE,'purpose':'native-deadline-sleeper'}:raise RuntimeError('intent mismatch')
 if cat.get('target_id')!=TARGET or cat.get('generation')!=TARGET or cat.get('boot_id')!=BOOT or (cat.get('cgroup_dev'),cat.get('cgroup_ino'))!=(29,7623397):raise RuntimeError('catalog mismatch')
 if grant.get('target_id')!=TARGET or grant.get('boot_id')!=BOOT or grant.get('catalog_sha256')!=FILES['catalog'][1] or grant.get('purpose')!='synthetic-canary-only':raise RuntimeError('grant mismatch')
 if armed.get('target')!=TARGET or armed.get('boot_id')!=BOOT or armed.get('grant_sha256')!=FILES['grant'][1] or armed.get('engine_effects') is not False or arm.get('selected_duration_seconds')!=19:raise RuntimeError('arm mismatch')
 if ob.get('target_id')!=TARGET or ob.get('boot_id')!=BOOT or (ob.get('cgroup_dev'),ob.get('cgroup_ino'))!=(29,7623397) or any(ob.get(k) is not True for k in ('observed','closed','frozen','empty')) or ob.get('engine_reconciled') is not False:raise RuntimeError('observation mismatch')
 observed=ob.get('observed_at_unix')
 # Kernel observation timestamp has whole-second precision; compare its entire
 # one-second interval against the issued time and expiry conservatively.
 if type(observed) is not int or observed*1_000_000_000<grant['issued_unix_ns'] or (observed+1)*1_000_000_000>grant['expires_unix_ns']:raise RuntimeError('deadline timing not established')
 try:(CGROUP/SLICE).lstat()
 except FileNotFoundError:pass
 else:raise RuntimeError('owned cgroup still exists')
 units={name:unit(name) for name in (ANCHOR,SLICE,TIMER,SERVICE)}
 for name in (TIMER,SERVICE):
  u=units[name]
  if u.get('LoadState')!='not-found' or u.get('ActiveState')!='inactive' or u.get('Job')!='' or u.get('Names')!=name or u.get('FragmentPath')!='' or u.get('DropInPaths')!='':raise RuntimeError('timer/service cleanup unresolved')
 a=units[ANCHOR]
 if a.get('LoadState')!='loaded' or a.get('ActiveState')!='failed' or a.get('Result')!='signal' or a.get('Job')!='' or a.get('Names')!=ANCHOR or a.get('Transient')!='yes' or a.get('FragmentPath')!='/run/systemd/transient/'+ANCHOR or a.get('DropInPaths')!='':raise RuntimeError('anchor identity mismatch')
 s=units[SLICE]
 if s.get('ActiveState')!='inactive' or s.get('Job')!='' or s.get('Names')!=SLICE:raise RuntimeError('slice manager state unresolved')
 return {'component':'root-deadline-reconcile','source_sha256':host.source_digest,'target':TARGET,'boot_id':BOOT,'evidence_sha256':{k:v[1] for k,v in FILES.items()},'cgroup_absent':True,'timer_service_collected':True,'anchor_failed_record_preserved':True,'observed_at_unix':observed,'deadline_expires_unix_ns':grant['expires_unix_ns'],'engine_reconciled':False}

def apply(host,reviewed):
 current=make_plan(host)
 if reviewed!=current:raise RuntimeError('reviewed evidence changed')
 obj={'target':TARGET,'boot_id':BOOT,'status':'reconciled_native_kernel_canary','initial_cleanup_outcome':'unknown_then_reconciled','same_inode_observation_from_protected_record':True,'timer_service_collected':True,'cgroup_absent':True,'anchor_failed_record_preserved':True,'engine_reconciled':False,'evidence_sha256':current['evidence_sha256'],'observed_at_unix':current['observed_at_unix'],'deadline_expires_unix_ns':current['deadline_expires_unix_ns']}
 fd=os.open(RECEIPT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'w') as f:
  s=os.fstat(f.fileno())
  if s.st_uid!=0 or s.st_gid!=0:raise RuntimeError('receipt owner mismatch')
  json.dump(obj,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)
 return {'target':TARGET,'receipt':str(RECEIPT),'status':'reconciled_native_kernel_canary','engine_reconciled':False}
