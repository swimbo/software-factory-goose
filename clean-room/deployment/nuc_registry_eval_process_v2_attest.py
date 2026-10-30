"""Create-only process/socket attestation for one active production evaluator."""
import hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
import nuc_registry_eval_snapshot_provision as snapshot
import nuc_registry_eval_service_v2_provision as service
import nuc_registry_transition_gate as gate
ROOT=old.ETC

def require(v,m):
 if not v:raise RuntimeError(m)
def _plan():
 g,reg,_=snapshot.selected();installed=json.loads(old.read(ROOT/(g+'.evaluator-service-complete.json'),0o600));intent=json.loads(old.read(ROOT/(g+'.evaluator-service-started.json'),0o600));require(installed=={'generation':g,'installed':True,'started':False,'fixture_only':False} and intent['registry_sha256']==reg,'service unavailable')
 name,_,_=service.bodies(g);unit=name+'.service';sockunit=name+'.socket';fragment=old.UNIT/unit;socket=old.RUN/'evaluator-production'/g/'broker.sock'
 snapshot.trusted_ancestry(ROOT);snapshot.trusted_ancestry(old.RUN);old.directory(old.PREFIX/'evaluator-production-v2',0,2002,0o750);old.directory(old.RUN/'evaluator-production',0,0,0o711);old.directory(old.RUN/'evaluator-production'/g,0,2002,0o710)
 unitraw=old.read(fragment,0o644,intent['service_sha256']);old.read(old.UNIT/sockunit,0o644,intent['socket_sha256'])
 for n in (unit,sockunit):
  for k,v in (('LoadState','loaded'),('ActiveState','active'),('Names',n),('FragmentPath',str(old.UNIT/n)),('DropInPaths',''),('Job','')):require(old.ctl('show',n,'-p',k,'--value')==v,'unit identity unavailable')
 pid=int(old.ctl('show',unit,'-p','MainPID','--value'));inv=old.ctl('show',unit,'-p','InvocationID','--value');require(pid>1 and re.fullmatch(r'[0-9a-f]{32}',inv),'process unavailable')
 f=dict(x.split(':',1) for x in pathlib.Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in x);require(f.get('Uid','').split()==['0']*4 and f.get('Gid','').split()==['0']*4 and f.get('NoNewPrivs','').strip()=='1' and all(int(f[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')),'process privileges unavailable')
 st=os.lstat(socket);require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2002,1,0o660),'socket unavailable')
 try:os.getxattr(socket,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==__import__('errno').ENODATA,'socket ACL unavailable')
 else:raise RuntimeError('socket ACL present')
 output=old.PREFIX/'evaluator-production-v2'/(g+'.broker-attestation.json');started=ROOT/(g+'.evaluator-attestation-started.json');done=ROOT/(g+'.evaluator-attestation-complete.json');require(not any(os.path.lexists(x) for x in (output,started,done)),'attestation occupied')
 return {'schema':1,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'generation':g,'pid':pid,'invocation_id':inv,'unit_sha256':hashlib.sha256(unitraw).hexdigest(),'socket_dev':st.st_dev,'socket_ino':st.st_ino}
def plan():
 with gate.admission():return _plan()
def apply(reviewed):
 with gate.admission():return _apply(reviewed)
def _apply(reviewed):
 require(_plan()==reviewed,'attestation changed');g=reviewed['generation'];started=ROOT/(g+'.evaluator-attestation-started.json');output=old.PREFIX/'evaluator-production-v2'/(g+'.broker-attestation.json');old.store(started,json.dumps(reviewed,sort_keys=True).encode()+b'\n',0o600)
 raw=json.dumps(reviewed,sort_keys=True,separators=(',',':')).encode();fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o440)
 try:
  os.fchown(fd,0,2002);os.fchmod(fd,0o440);view=memoryview(raw)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(output.parent);result={'generation':g,'attestation_sha256':hashlib.sha256(raw).hexdigest(),'fixture_only':False};old.store(ROOT/(g+'.evaluator-attestation-complete.json'),json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
