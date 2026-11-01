"""Recover owned FD canary: observe original positive, run only fresh negative."""
import json,os,pathlib,re,socket,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
import nuc_sdk5_fd_guard_canary as original
SOURCE=None;SOURCE_SHA='f3fbcd0ac9d3803fa8b2db7c4276c94da162bbffa71ad8da38f2482137b0b9ef'
WRAPPER=old.PREFIX/'sdk5-guard-canary-extra-v2.py';EXTRA=old.RUN/'sdk5-guard-canary-extra-v2.sock';NEG='sfactory-sdk5-fdguard-canary-negative-v2.service'
START=old.ETC/'sdk5-fdguard-canary-recovery-started.json';DONE=old.ETC/'sdk5-fdguard-canary-recovery-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def unit():return original.units()[original.NEG].replace(str(original.WRAPPER).encode(),str(WRAPPER).encode())
def positive():
 name=original.POS;props={k:old.ctl('show',name,'-p',k,'--value') for k in ('Names','LoadState','ActiveState','SubState','MainPID','Job','Result','ExecMainStatus','InvocationID','User','Group','NoNewPrivileges','CapabilityBoundingSet','FragmentPath','DropInPaths')}
 require(props['Names']==name and props['LoadState']=='loaded' and props['ActiveState']=='active' and props['SubState']=='exited' and props['MainPID']=='0' and props['Job']=='' and props['Result']=='success' and props['ExecMainStatus']=='0' and props['User']=='sfgoose-control' and props['Group']=='sfgoose-control' and props['NoNewPrivileges']=='yes' and props['CapabilityBoundingSet']=='' and props['FragmentPath']==str(old.UNIT/name) and props['DropInPaths']=='' and re.fullmatch(r'[0-9a-f]{32}',props['InvocationID']) and props['InvocationID']!='0'*32,'positive identity unavailable')
 require(b'sdk5-startup-guard-passed\n' in original.journal(name,props['InvocationID']),'positive journal unavailable');return props['InvocationID']
def plan():
 require(os.geteuid()==0 and isinstance(SOURCE,bytes) and base.sha(SOURCE)==SOURCE_SHA,'recovery source unavailable');require(not any(os.path.lexists(x) for x in (WRAPPER,EXTRA,START,DONE,old.UNIT/NEG)),'recovery occupied')
 prior=json.loads(old.read(original.START,0o600));require(prior.get('binary',{}).get('sha256')==original.BINARY_SHA and prior.get('wrapper_sha256')==original.SOURCE_SHA and prior.get('units')=={n:base.sha(v) for n,v in original.units().items()},'original intent changed')
 old.read(original.BINARY,0o755,original.BINARY_SHA,10_000_000);old.read(original.WRAPPER,0o755,original.SOURCE_SHA)
 for name,data in original.units().items():
  old.read(old.UNIT/name,0o644,base.sha(data));require(old.ctl('show',name,'-p','Names','--value')==name and old.ctl('show',name,'-p','FragmentPath','--value')==str(old.UNIT/name) and old.ctl('show',name,'-p','DropInPaths','--value')=='','original unit changed')
 require(old.ctl('show',original.NEG,'-p','ActiveState','--value')=='inactive' and old.ctl('show',original.NEG,'-p','MainPID','--value')=='0' and old.ctl('show',original.NEG,'-p','Job','--value')=='','old negative not untouched')
 for name in original.SOCKETS:require(old.ctl('show',name,'-p','ActiveState','--value')=='active' and old.ctl('show',name,'-p','Job','--value')=='','fixture socket unavailable')
 inv=positive();require(old.ctl('show',NEG,'-p','LoadState','--value')=='not-found','negative unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable');stem=NEG.removesuffix('.service')
 for parent in map(pathlib.Path,paths):
  for n in [NEG,NEG+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(parent/n),'unit collision')
 return {'schema':1,'original_intent_sha256':base.sha(old.read(original.START,0o600)),'positive_invocation_id':inv,'negative_unit_sha256':base.sha(unit()),'wrapper_sha256':SOURCE_SHA,'scope':'run only fresh negative; preserve original attempt'}
def apply(approved):
 require(plan()==approved,'recovery changed');old.store(START,base.canonical(approved)+b'\n',0o600);old.store(WRAPPER,SOURCE,0o755);old.store(old.UNIT/NEG,unit(),0o644);old.ctl('daemon-reload');old.read(old.UNIT/NEG,0o644,approved['negative_unit_sha256'])
 require(old.ctl('show',NEG,'-p','Names','--value')==NEG and old.ctl('show',NEG,'-p','FragmentPath','--value')==str(old.UNIT/NEG) and old.ctl('show',NEG,'-p','DropInPaths','--value')=='','negative unit changed')
 listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
 try:
  listener.bind(str(EXTRA));os.chmod(EXTRA,0o666);listener.listen(2);created=os.lstat(EXTRA);require(stat.S_ISSOCK(created.st_mode) and created.st_uid==0,'extra socket unavailable');old.syncdir(EXTRA.parent)
  require(positive()==approved['positive_invocation_id'],'positive changed');p=subprocess.run(['/usr/bin/systemctl','start',NEG],env=old.ENV,capture_output=True,timeout=40,check=False);require(p.returncode!=0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'negative outcome unknown')
  fields={k:old.ctl('show',NEG,'-p',k,'--value') for k in ('Names','LoadState','ActiveState','MainPID','Job','Result','ExecMainStatus','InvocationID','User','Group','NoNewPrivileges','CapabilityBoundingSet','FragmentPath','DropInPaths')};inv=fields['InvocationID']
  require(fields['Names']==NEG and fields['LoadState']=='loaded' and fields['ActiveState']=='failed' and fields['MainPID']=='0' and fields['Job']=='' and fields['Result']=='exit-code' and fields['ExecMainStatus']!='0' and fields['User']=='sfgoose-control' and fields['Group']=='sfgoose-control' and fields['NoNewPrivileges']=='yes' and fields['CapabilityBoundingSet']=='' and fields['FragmentPath']==str(old.UNIT/NEG) and fields['DropInPaths']=='' and re.fullmatch(r'[0-9a-f]{32}',inv) and inv!='0'*32,'negative identity unavailable')
  require(b'unexpected inherited descriptor' in original.journal(NEG,inv),'negative denial unavailable')
  for name in (NEG,original.NEG,original.POS,*original.SOCKETS):
   old.ctl('stop',name);require(old.ctl('show',name,'-p','ActiveState','--value') in ('inactive','failed') and old.ctl('show',name,'-p','Job','--value')=='','cleanup unknown')
   if name.endswith('.service'):
    require(old.ctl('show',name,'-p','MainPID','--value')=='0','process remains');cg=pathlib.Path('/sys/fs/cgroup/system.slice')/name
    try:st=os.lstat(cg)
    except FileNotFoundError:st=None
    if st is not None:require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'cgroup populated')
 finally:listener.close()
 for path in original.PATHS:require(not os.path.lexists(path),'fixture socket remains')
 st=os.lstat(EXTRA);require(stat.S_ISSOCK(st.st_mode) and st.st_uid==0 and (st.st_dev,st.st_ino)==(created.st_dev,created.st_ino),'extra socket changed');os.unlink(EXTRA);old.syncdir(EXTRA.parent)
 # Preserve original and new unit files and the prior unpinned extra socket for diagnosis.
 result={'schema':1,'positive':True,'extra_connected_fd_denied':True,'positive_invocation_id':approved['positive_invocation_id'],'negative_invocation_id':inv,'fixture_stopped':True,'registration':False,'original_attempt_retained':True};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
