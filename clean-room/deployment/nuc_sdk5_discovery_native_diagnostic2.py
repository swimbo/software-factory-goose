"""Owned native PID1 discovery control. No Restate, journal or provider."""
import hashlib,json,os,pathlib,selectors,stat,subprocess,time
import nuc_grant_sidecar_install as old
import nuc_registry_offline_backup as backup
import nuc_registry_sdk5_discovery_install as probe

ROOT=pathlib.Path('/var/lib/software-factory-goose/sdk5-discovery-diagnostic2')
SERVER_STAGE=pathlib.Path('/tmp/sfactory-sdk5-discovery-fixture-20261030/server')
SERVER_SHA='33e511e62ffa4c2fe23434921cc82cbbc75a16613d9acad0604b2bc3275f06bc'
SERVER=ROOT/'server';CLIENT=ROOT/'probe';WRAPPER=ROOT/'extra.py'
START=old.ETC/'sdk5-discovery-native-diagnostic2-started.json';DONE=old.ETC/'sdk5-discovery-native-diagnostic2-complete.json'
NET='sfactory-sdk5-discovery-diagnostic2-net.service';SERVER_UNIT='sfactory-sdk5-discovery-diagnostic2-server.service';NS='sfactory-sdk5-discovery-diagnostic2-namespace.service';CHECK='sfactory-sdk5-discovery-diagnostic2-listener.service';POS='sfactory-sdk5-discovery-diagnostic2-positive.service';NEG='sfactory-sdk5-discovery-diagnostic2-negative.service'
WRAPPER_BYTES=b"import os,socket\ns=socket.create_connection(('127.0.0.1',9085),timeout=3)\nos.set_inheritable(s.fileno(),True)\nos.execv('/var/lib/software-factory-goose/sdk5-discovery-diagnostic2/probe',['probe'])\n"
def require(v,m):
 if not v:raise RuntimeError(m)
def stage(path,sha,dest=None):
 before=(old.SOURCE,old.SOURCE_SHA)
 try:old.SOURCE=path;old.SOURCE_SHA=sha;return old.binary(dest)
 finally:old.SOURCE,old.SOURCE_SHA=before
def collision(name,paths):
 stem=name.removesuffix('.service')
 for path in map(pathlib.Path,paths):
  for item in [name,name+'.d','service.d']+[stem[:i+1]+'.service.d' for i,c in enumerate(stem) if c=='-']:
   require(not os.path.lexists(path/item),'unit collision')
def plan():
 require(os.geteuid()==0 and SERVER_SHA is not None,'staged server unavailable')
 require(not any(os.path.lexists(p) for p in (ROOT,START,DONE)),'canary occupied')
 old.directory(ROOT.parent,0,0,0o711);old.directory(old.ETC,0,0,0o711);old.directory(SERVER_STAGE.parent,1000,1000,0o700);old.directory(probe.SOURCE.parent,1000,1000,0o700)
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 for unit in (NET,SERVER_UNIT,NS,CHECK,POS,NEG):
  require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','unit occupied');collision(unit,paths)
 return {'schema':1,'server':stage(SERVER_STAGE,SERVER_SHA),'probe':stage(probe.SOURCE,probe.SOURCE_SHA),'wrapper_sha256':hashlib.sha256(WRAPPER_BYTES).hexdigest(),'scope':'isolated native discovery and inherited descriptor rejection; no registration'}
def props(unit):return {k:old.ctl('show',unit,'-p',k,'--value') for k in ('ActiveState','MainPID','Job')}
def identity(unit):
 p=props(unit);pid=int(p['MainPID']);inv=old.ctl('show',unit,'-p','InvocationID','--value');require(p['ActiveState']=='active' and pid>1 and not p['Job'] and len(inv)==32 and all(c in '0123456789abcdef' for c in inv) and inv!='0'*32 and old.ctl('show',unit,'-p','Names','--value')==unit,'unit identity unavailable')
 ticks=int(pathlib.Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]);cg=os.lstat(pathlib.Path('/sys/fs/cgroup/system.slice')/unit);require(stat.S_ISDIR(cg.st_mode) and cg.st_uid==0 and cg.st_gid==0,'unit cgroup unavailable')
 return {'pid':pid,'invocation':inv,'ticks':ticks,'dev':cg.st_dev,'ino':cg.st_ino}
def stopped(unit,expected=None):
 p=props(unit);require(p['ActiveState'] in ('inactive','failed') and p['MainPID']=='0' and not p['Job'],'unit outcome unknown')
 cg=pathlib.Path('/sys/fs/cgroup/system.slice')/unit
 try:st=os.lstat(cg)
 except FileNotFoundError:return
 require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and st.st_gid==0 and (expected is None or (st.st_dev,st.st_ino)==(expected['dev'],expected['ino'])) and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'unit cgroup unresolved')
def run(unit,command,wait=False,root=False):
 args=['/usr/bin/systemd-run','--unit='+unit,'--quiet']+(['--wait','--pipe'] if wait else [])+[('--property=User=root' if root else '--property=User=sfgoose-control'),('--property=Group=root' if root else '--property=Group=sfgoose-control'),'--property=PrivateNetwork=yes','--property=JoinsNamespaceOf='+NET,'--property=BindsTo='+NET,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=30s','--property=StandardInput=null',*command]
 if unit not in (POS,NEG):return subprocess.run(args,env=old.ENV,capture_output=True,timeout=40,check=False)
 paths=[ROOT/(("positive" if unit==POS else "negative")+"-"+x) for x in ("stdout","stderr")]
 fds=[];proc=None;selector=selectors.DefaultSelector();counts=[0,0];failed=None
 try:
  for path in paths:
   fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);os.fchmod(fd,0o600);fds.append(fd)
  old.syncdir(ROOT)
  proc=subprocess.Popen(args,env=old.ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  for i,stream in enumerate((proc.stdout,proc.stderr)):
   os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,i)
  deadline=time.monotonic()+40
  while selector.get_map():
   remaining=deadline-time.monotonic()
   if remaining<=0:failed='probe timeout';break
   for key,_ in selector.select(min(remaining,.5)):
    chunk=os.read(key.fileobj.fileno(),8193)
    if not chunk:selector.unregister(key.fileobj);key.fileobj.close();continue
    i=key.data;counts[i]+=len(chunk)
    if counts[i]>8192:failed='probe output oversized';break
    view=memoryview(chunk)
    while view:
     n=os.write(fds[i],view);require(n>0,'short capture write');view=view[n:]
   if failed:break
  if failed:proc.kill()
  try:code=proc.wait(timeout=5)
  except subprocess.TimeoutExpired:
   proc.kill();failed='probe wait unknown'
   try:proc.wait(timeout=5)
   except subprocess.TimeoutExpired:pass
  for fd in fds:os.fsync(fd)
 finally:
  selector.close()
  if proc is not None and proc.poll() is None:
   proc.kill()
   try:proc.wait(timeout=5)
   except subprocess.TimeoutExpired:pass
  for fd in fds:os.close(fd)
 if failed:raise RuntimeError(failed)
 outputs=[path.read_bytes() for path in paths]
 return subprocess.CompletedProcess(args,code,*outputs)

def apply(approved):
 require(plan()==approved,'canary plan changed');old.store(START,backup.canonical(approved),0o600)
 os.mkdir(ROOT,0o755);os.chmod(ROOT,0o755);old.syncdir(ROOT.parent);require(stage(SERVER_STAGE,SERVER_SHA,SERVER)==approved['server'] and stage(probe.SOURCE,probe.SOURCE_SHA,CLIENT)==approved['probe'],'binary changed');old.store(WRAPPER,WRAPPER_BYTES,0o755)
 result=subprocess.run(['/usr/bin/systemd-run','--unit='+NET,'--quiet','--property=PrivateNetwork=yes','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=RuntimeMaxSec=90s','/usr/bin/sleep','80'],env=old.ENV,capture_output=True,timeout=15,check=False);require(result.returncode==0,'namespace start unknown');net_identity=identity(NET)
 host=json.loads(old.read(old.RUN/'host-netns.json',0o600));private=json.loads(old.read(old.RUN/'private-netns.json',0o600));require(host.get('role')=='host' and private.get('role')=='private' and host.get('uid')==0 and private.get('uid')==0 and all(type(x.get(k)) is int and x[k]>0 for x in (host,private) for k in ('pid','netns_dev','netns_ino')),'anchor observations unavailable')
 require(old.ctl('show','software-factory-goose-private-host-net.service','-p','MainPID','--value')==str(host['pid']) and old.ctl('show','software-factory-goose-private-net.service','-p','MainPID','--value')==str(private['pid']),'anchor changed')
 ns=run(NS,['/usr/bin/python3','-I','-B','-c',"import os; s=os.stat('/proc/self/ns/net');print(str(s.st_dev)+' '+str(s.st_ino))"],True,root=True);require(ns.returncode==0 and len(ns.stdout)<=80 and len(ns.stderr)<=8192,'namespace observation unknown');stopped(NS)
 fields=ns.stdout.decode().strip().split();require(len(fields)==2 and all(x.isdecimal() and int(x)>0 for x in fields),'namespace identity unavailable');observed=tuple(map(int,fields));require(observed not in ((host['netns_dev'],host['netns_ino']),(private['netns_dev'],private['netns_ino'])) and identity(NET)==net_identity,'namespace isolation unavailable')
 result=run(SERVER_UNIT,[str(SERVER)]);require(result.returncode==0,'server start unknown')
 # Discovery retries here are deliberately forbidden: readiness must be established before a single probe.
 until=time.monotonic()+10
 while time.monotonic()<until:
  if old.ctl('show',SERVER_UNIT,'-p','ActiveState','--value')=='active':break
  time.sleep(.1)
 require(old.ctl('show',SERVER_UNIT,'-p','ActiveState','--value')=='active','server not active');server_identity=identity(SERVER_UNIT)
 check=run(CHECK,['/usr/bin/python3','-I','-B','-c',"import socket,time; deadline=time.monotonic()+8\nwhile True:\n try: s=socket.create_connection(('127.0.0.1',9085),timeout=1);s.close();break\n except OSError:\n  if time.monotonic()>=deadline:raise\n  time.sleep(.1)"],True);require(check.returncode==0 and not check.stdout and len(check.stderr)<=8192,'listener unavailable');stopped(CHECK)
 pos=run(POS,[str(CLIENT)],True);require(pos.returncode==0 and pos.stdout==b'sdk5-discovery-verified\n' and len(pos.stderr)<=8192,'positive discovery unknown');stopped(POS)
 neg=run(NEG,['/usr/bin/python3','-I','-B',str(WRAPPER)],True);require(neg.returncode!=0 and not neg.stdout and b'unexpected inherited descriptor' in neg.stderr and len(neg.stderr)<=8192,'extra descriptor outcome unknown');stopped(NEG)
 for unit,expected in ((SERVER_UNIT,server_identity),(NET,net_identity)):
  require(identity(unit)==expected,'unit replaced');old.ctl('stop',unit);stopped(unit,expected)
 result={'schema':1,'probe_sha256':probe.SOURCE_SHA,'server_sha256':SERVER_SHA,'positive_discovery':True,'inherited_connected_fd_denied':True,'units_stopped':True,'registration':False,'production_changed':False};old.store(DONE,backup.canonical(result),0o600);return result
