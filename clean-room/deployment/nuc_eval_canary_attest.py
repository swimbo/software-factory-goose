"""Create-only attestation of the synthetic evaluator broker's actual unit."""
import hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
NAME='software-factory-goose-eval-canary';DEST=old.PREFIX/'evaluator';ATTEST=DEST/'broker-attestation.json';START=old.ETC/'evaluator-canary-attestation-started.json';DONE=old.ETC/'evaluator-canary-attestation-complete.json';SOCKET=old.RUN/'evaluator'/'broker.sock';G='01M65RMR3F04YB1B016EBBSXGK'
def require(x,msg):
 if not x:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (ATTEST,START,DONE)),'attestation occupied')
 old.directory(DEST,0,2002,0o710);old.directory(SOCKET.parent,0,2002,0o710)
 receipt=json.loads(old.read(old.ETC/'evaluator-canary-service-complete.json',0o600));require(receipt=={'generation':G,'installed':True,'started':False,'fixture_only':True},'fixture installation unavailable')
 source_plan=json.loads(old.read(old.ETC/'evaluator-canary-provision-started.json',0o600));pins=source_plan['source_sha256'];require(isinstance(pins,dict) and len(pins)==12,'source manifest unavailable')
 upgrade=json.loads(old.read(old.ETC/'evaluator-canary-backend-v2-complete.json',0o600));require(upgrade=={'generation':G,'backend_sha256':'dc8cb24e1bda8f0ed525f80216c1c4361b8889f588287b3eaf44eb946368cffc','previous_sha256':pins.get('nuc_registry_eval_backend.py'),'fixture_only':True,'activated':False},'backend upgrade unavailable');pins=dict(pins);pins['nuc_registry_eval_backend.py']=upgrade['backend_sha256']
 runtime=json.loads(old.read(old.ETC/'evaluator-canary-runtime-v2-complete.json',0o600));require(runtime=={'generation':G,'runtime_sha256':'217d03d78d642db1aa0162c934aadd573905c7c7784328ada308f7e9585ac48d','previous_sha256':pins.get('nuc_registry_eval_canary_runtime.py'),'fixture_only':True,'activated':False},'runtime upgrade unavailable');pins['nuc_registry_eval_canary_runtime.py']=runtime['runtime_sha256']
 parent=os.open(DEST,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for name,digest in pins.items():
   require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_.-]+',name) and name not in ('.','..') and isinstance(digest,str) and re.fullmatch(r'[0-9a-f]{64}',digest),'source pin invalid')
   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
   try:
    st=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2002,1,0o440) and st.st_size<=1000000,'source unavailable');data=os.read(fd,1000001);require(len(data)==st.st_size and hashlib.sha256(data).hexdigest()==digest,'source changed')
   finally:os.close(fd)
 finally:os.close(parent)
 intent=json.loads(old.read(old.ETC/'evaluator-canary-service-started.json',0o600));unit=old.UNIT/(NAME+'.service');unit_raw=old.read(unit,0o644,intent['service_sha256'])
 prop=dict(line.split('=',1) for line in old.ctl('show',NAME+'.service','--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,InvocationID,User,Group,NoNewPrivileges,CapabilityBoundingSet,ControlGroup,ExecStart','--all','--no-pager').splitlines());pid=int(prop.get('MainPID','0'));inv=prop.get('InvocationID','')
 require(prop.get('LoadState')=='loaded' and prop.get('ActiveState')=='active' and pid>1 and re.fullmatch('[0-9a-f]{32}',inv or '') and prop.get('Names')==NAME+'.service' and prop.get('FragmentPath')==str(unit) and prop.get('DropInPaths','')=='' and prop.get('User')=='root' and prop.get('Group')=='root' and prop.get('NoNewPrivileges')=='yes' and prop.get('CapabilityBoundingSet')=='' and prop.get('ControlGroup')=='/system.slice/'+NAME+'.service','unit unavailable')
 command=prop.get('ExecStart','');require(command.startswith('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+str(DEST/'nuc_registry_eval_canary_runtime.py')+' ; ignore_errors=no ;') and command.count('{ path=')==1,'runtime changed')
 fields=dict(line.split(':',1) for line in pathlib.Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line);require(fields.get('Uid','').split()==['0']*4 and fields.get('Gid','').split()==['0']*4 and fields.get('NoNewPrivs','').strip()=='1' and all(int(fields[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')),'runtime privileges differ')
 s=os.lstat(SOCKET);require(stat.S_ISSOCK(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2002,1,0o660),'socket unavailable')
 try:os.getxattr(SOCKET,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==old.errno.ENODATA,'socket ACL unavailable')
 else:raise RuntimeError('socket ACL forbidden')
 again=dict(line.split('=',1) for line in old.ctl('show',NAME+'.service','--property=MainPID,InvocationID','--no-pager').splitlines());require(again=={'MainPID':str(pid),'InvocationID':inv},'runtime changed during attestation')
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();return {'schema':1,'boot_id':boot,'generation':G,'pid':pid,'invocation_id':inv,'unit_sha256':hashlib.sha256(unit_raw).hexdigest(),'socket_dev':s.st_dev,'socket_ino':s.st_ino}
def apply(approved):
 require(plan()==approved,'attestation changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 fd=os.open(ATTEST,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o440)
 try:
  body=json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n';view=memoryview(body)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fchmod(fd,0o440);os.fchown(fd,0,2002);os.fsync(fd)
 finally:os.close(fd)
 old.syncdir(DEST);result={'generation':G,'manifest_sha256':hashlib.sha256(body).hexdigest(),'pid':approved['pid'],'fixture_only':True};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
