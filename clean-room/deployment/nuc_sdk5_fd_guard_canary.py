"""Owned native SDK5 pre-runtime FD guard canary; no SDK registration or Restate."""
import json,os,pathlib,re,socket,stat,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_unix_admin_h2_install as base
SOURCE=None;SOURCE_SHA='b545b90dfb1804e14fe3fbf53023cd0eeba4056f1457a3d7cd163a8f7e450eb0'
STAGE=pathlib.Path('/tmp/sfactory-sdk5-fdguard-20261030/sdk5-guard-canary-v2');BINARY_SHA='e6c12ae30c1903566f05e46b9baa064ac65bd9e7e873bd78204e5ab66d256beb'
BINARY=old.PREFIX/'sdk5-startup-guard-canary';WRAPPER=old.PREFIX/'sdk5-guard-canary-extra.py'
PREFIX='sfactory-sdk5-fdguard-canary-';POS=PREFIX+'positive.service';NEG=PREFIX+'negative.service'
SOCKETS=[PREFIX+x+'.socket' for x in ('intake','worker','launch')]
PATHS=[old.RUN/('sdk5-guard-canary-'+x+'.sock') for x in ('intake','worker','launch')];EXTRA=old.RUN/'sdk5-guard-canary-extra.sock'
START=old.ETC/'sdk5-fdguard-canary-started.json';DONE=old.ETC/'sdk5-fdguard-canary-complete.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def binary(dest=None):
 prior=(old.SOURCE,old.SOURCE_SHA)
 try:old.SOURCE=STAGE;old.SOURCE_SHA=BINARY_SHA;return old.binary(dest)
 finally:old.SOURCE,old.SOURCE_SHA=prior
def units():
 out={}
 for name,path,fd in zip(SOCKETS,PATHS,('intake','worker','launch-grant')):
  out[name]=('[Socket]\nListenStream='+str(path)+'\nSocketUser=root\nSocketGroup=sfgoose-control\nSocketMode=0660\nRemoveOnStop=yes\nFileDescriptorName='+fd+'\nService='+POS+'\n').encode()
 for name,cmd in ((POS,str(BINARY)),(NEG,'/usr/bin/python3 -I -B '+str(WRAPPER))):
  out[name]=('[Unit]\nDescription=Owned SDK5 FD guard canary\n[Service]\nType=oneshot\nRemainAfterExit=yes\nUser=sfgoose-control\nGroup=sfgoose-control\nSockets='+' '.join(SOCKETS)+'\nStandardInput=null\nStandardOutput=journal\nStandardError=journal\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nMemoryMax=128M\nTasksMax=16\nRuntimeMaxSec=30s\nExecStart='+cmd+'\n').encode()
 return out
def plan():
 require(os.geteuid()==0 and isinstance(SOURCE,bytes) and base.sha(SOURCE)==SOURCE_SHA,'wrapper unavailable')
 require(not any(os.path.lexists(p) for p in (BINARY,WRAPPER,EXTRA,START,DONE,*PATHS)),'canary occupied');old.directory(old.RUN,0,0,0o755);old.directory(old.PREFIX,0,0,0o755)
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for name in units():
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','unit occupied');stem=name.rsplit('.',1)[0]
  for parent in map(pathlib.Path,paths):
   for n in [name,name+'.d',name.rsplit('.',1)[1]+'.d']+[stem[:i+1]+'.'+name.rsplit('.',1)[1]+'.d' for i,c in enumerate(stem) if c=='-']:require(not os.path.lexists(parent/n),'unit collision')
 return {'schema':1,'binary':binary(),'wrapper_sha256':SOURCE_SHA,'units':{n:base.sha(v) for n,v in units().items()},'scope':'one native PID1 socket activation positive and connected-extra-FD negative; no SDK registration'}
def terminal(name,success):
 p={k:old.ctl('show',name,'-p',k,'--value') for k in ('Names','LoadState','ActiveState','SubState','MainPID','Job','Result','ExecMainStatus','InvocationID','User','Group','NoNewPrivileges','CapabilityBoundingSet','Sockets')}
 require(p['Names']==name and p['LoadState']=='loaded' and p['MainPID']=='0' and p['Job']=='' and p['User']=='sfgoose-control' and p['Group']=='sfgoose-control' and p['NoNewPrivileges']=='yes' and p['CapabilityBoundingSet']=='' and set(p['Sockets'].split())==set(SOCKETS),'service identity unavailable')
 require((p['Result']=='success' and p['ExecMainStatus']=='0' and p['ActiveState']=='active' and p['SubState']=='exited') if success else (p['Result']=='exit-code' and p['ExecMainStatus']!='0' and p['ActiveState']=='failed'),'service outcome unknown')
 require(re.fullmatch(r'[0-9a-f]{32}',p['InvocationID']) and p['InvocationID']!='0'*32,'invocation unavailable')
 return p
def journal(name,invocation):
 p=subprocess.run(['/usr/bin/journalctl','--boot','--unit='+name,'--no-pager','--output=cat','--lines=100','_SYSTEMD_INVOCATION_ID='+invocation],env=old.ENV,capture_output=True,timeout=10,check=False);require(p.returncode==0 and len(p.stdout)<=16384 and len(p.stderr)<=4096,'journal unavailable');return p.stdout
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,base.canonical(approved)+b'\n',0o600)
 require(binary(BINARY)==approved['binary'],'binary changed');old.syncdir(BINARY.parent);old.read(BINARY,0o755,BINARY_SHA,10_000_000);old.store(WRAPPER,SOURCE,0o755)
 for name,data in units().items():old.store(old.UNIT/name,data,0o644)
 old.ctl('daemon-reload')
 for name,data in units().items():
  old.read(old.UNIT/name,0o644,base.sha(data));require(old.ctl('show',name,'-p','Names','--value')==name and old.ctl('show',name,'-p','FragmentPath','--value')==str(old.UNIT/name) and old.ctl('show',name,'-p','DropInPaths','--value')=='','unit changed')
 listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
 try:
  listener.bind(str(EXTRA));os.chmod(EXTRA,0o666);listener.listen(2);created=os.lstat(EXTRA);require(stat.S_ISSOCK(created.st_mode) and created.st_uid==0,'extra socket unavailable');old.syncdir(EXTRA.parent)
  for name in SOCKETS:old.ctl('start',name)
  old.ctl('start',POS);positive=terminal(POS,True);require(b'sdk5-startup-guard-passed\n' in journal(POS,positive['InvocationID']),'positive evidence unavailable')
  p=subprocess.run(['/usr/bin/systemctl','start',NEG],env=old.ENV,capture_output=True,timeout=40,check=False);require(p.returncode!=0 and len(p.stdout)<=4096 and len(p.stderr)<=4096,'negative outcome unknown');negative=terminal(NEG,False);require(b'unexpected inherited descriptor' in journal(NEG,negative['InvocationID']),'negative evidence unavailable')
  for name in (NEG,POS,*SOCKETS):
   old.ctl('stop',name);require(old.ctl('show',name,'-p','ActiveState','--value') in ('inactive','failed') and old.ctl('show',name,'-p','Job','--value')=='','cleanup unknown')
   if name in (NEG,POS):
    require(old.ctl('show',name,'-p','MainPID','--value')=='0','service still running')
    cg=pathlib.Path('/sys/fs/cgroup/system.slice')/name
    try:st=os.lstat(cg)
    except FileNotFoundError:st=None
    if st is not None:require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'service cgroup not empty')
 finally:listener.close()
 # Success cleanup removes only objects created by this intent; unknown retains all files.
 for path in PATHS:require(not os.path.lexists(path),'socket remains')
 st=os.lstat(EXTRA);require(stat.S_ISSOCK(st.st_mode) and st.st_uid==0 and (st.st_dev,st.st_ino)==(created.st_dev,created.st_ino),'extra socket changed');os.unlink(EXTRA);old.syncdir(EXTRA.parent)
 for name,data in units().items():old.read(old.UNIT/name,0o644,base.sha(data));os.unlink(old.UNIT/name)
 old.syncdir(old.UNIT);old.ctl('daemon-reload')
 result={'schema':1,'positive':True,'extra_connected_fd_denied':True,'positive_unit':positive['Names'],'negative_unit':negative['Names'],'fixture_stopped':True,'registration':False};old.store(DONE,base.canonical(result)+b'\n',0o600);return result
