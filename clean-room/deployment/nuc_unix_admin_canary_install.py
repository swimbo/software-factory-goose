"""Create-only isolated Restate Unix-admin canary installation; never start units."""
import hashlib,json,os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
ROOT=pathlib.Path('/var/lib/software-factory-goose/unix-admin-canary')
DATA=ROOT/'data';CONFIG=old.ETC/'unix-admin-canary.toml';ANCHOR=old.PREFIX/'unix-admin-canary-anchor.py';PROBE=old.PREFIX/'unix-admin-canary-probe.py'
START=old.ETC/'unix-admin-canary-install-started.json';DONE=old.ETC/'unix-admin-canary-install-complete.json'
NET='sfactory-unix-admin-canary-net.service';SERVER='sfactory-unix-admin-canary-restate.service'
REST=old.PREFIX/'private-restate';REST_SHA='a45eba5044e331636b9da5a8f37fc901dec4cd3ccfcb10889241f76fe9c209db'
CONF=b'listen-mode = "tcp"\n[admin]\nlisten-mode = "unix"\n'
ANCHOR_SOURCE=b'#!/usr/bin/python3\nimport time\ntime.sleep(1200)\n'
PROBE_SOURCE=r'''#!/usr/bin/python3
import errno,http.client,json,os,socket,stat,sys
P='/var/lib/software-factory-goose/unix-admin-canary/data/sfactory-unix-admin/admin.sock'
s=open('/proc/self/status').read();assert 'NoNewPrivs:\t1' in s and all(('Cap'+x+':\t0000000000000000') in s for x in ('Inh','Prm','Eff','Bnd','Amb'))
assert len(sys.argv)==2 and sys.argv[1] in ('journal','control')
uid={'journal':2004,'control':2000}[sys.argv[1]];assert (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(uid,uid,uid,uid)
t=socket.socket();t.settimeout(2)
try:t.connect(('127.0.0.1',9070))
except ConnectionRefusedError:pass
else:raise RuntimeError('TCP admin reachable')
finally:t.close()
for table in ('/proc/self/net/tcp','/proc/self/net/tcp6'):
 for line in open(table).read().splitlines()[1:]:
  fields=line.split();assert not (fields[1].rsplit(':',1)[1].upper()=='236E' and fields[3]=='0A')
if uid==2000:
 u=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
 try:u.connect(P)
 except PermissionError:print(json.dumps({'tcp_denied':True,'unix_denied':True}));sys.exit(0)
 finally:u.close()
 raise RuntimeError('control reached admin')
st=os.lstat(P);assert stat.S_ISSOCK(st.st_mode) and st.st_uid==2004
try:os.getxattr(P,'system.posix_acl_access',follow_symlinks=False)
except OSError as e:assert e.errno==errno.ENODATA
else:raise RuntimeError('socket ACL present')
class Conn(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5);self.sock.connect(P)
c=Conn('localhost',timeout=5)
try:
 c.request('GET','/deployments',headers={'Accept':'application/json'});r=c.getresponse();body=r.read(65537);assert r.status==200 and len(body)<=65536
 print(json.dumps({'tcp_denied':True,'admin_ok':True,'socket_dev':st.st_dev,'socket_ino':st.st_ino,'socket_uid':st.st_uid,'socket_gid':st.st_gid,'socket_mode':stat.S_IMODE(st.st_mode)}))
finally:c.close()
'''.encode()
def require(v,m):
 if not v:raise RuntimeError(m)
def sha(v):return hashlib.sha256(v).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def verify_restate():
 fd=os.open(REST,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,0,1,0o755) and 0<s.st_size<=300_000_000,'restate identity');old.noacl(fd);h=hashlib.sha256();total=0
  while b:=os.read(fd,65536):total+=len(b);require(total<=s.st_size,'restate grew');h.update(b)
  require(total==s.st_size and h.hexdigest()==REST_SHA,'restate changed');return {'dev':s.st_dev,'ino':s.st_ino,'size':total,'sha256':REST_SHA}
 finally:os.close(fd)
def units():
 return {NET:('''[Unit]\nDescription=Owned disposable Unix admin canary namespace\n[Service]\nType=exec\nUser=root\nGroup=root\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestart=no\nMemoryMax=64M\nTasksMax=16\nRuntimeMaxSec=1200s\nExecStart=/usr/bin/python3 -I -B %s\n'''%ANCHOR).encode(),SERVER:('''[Unit]\nDescription=Owned disposable Unix admin Restate canary\nBindsTo=%s\nAfter=%s\nJoinsNamespaceOf=%s\n[Service]\nType=exec\nUser=sfgoose-journal\nGroup=sfgoose-journal\nPrivateNetwork=yes\nProtectSystem=strict\nReadWritePaths=%s\nProtectHome=yes\nPrivateTmp=yes\nUMask=0077\nEnvironment=TOKIO_WORKER_THREADS=2\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestart=no\nMemoryMax=2G\nTasksMax=128\nCPUQuota=100%%\nRuntimeMaxSec=1200s\nExecStart=%s --config-file %s --base-dir %s --node-name sfactory-unix-admin --bind-ip 127.0.0.1 --use-random-ports false --no-logo\n'''%(NET,NET,NET,DATA,REST,CONFIG,DATA)).encode()}
def plan():
 require(os.geteuid()==0,'root required')
 for p,u,g,m in [(ROOT.parent,0,0,0o711),(old.ETC,0,0,0o711),(old.PREFIX,0,0,0o755),(old.UNIT,0,0,0o755)]:old.directory(p,u,g,m)
 restate=verify_restate()
 paths=[ROOT,CONFIG,ANCHOR,PROBE,START,DONE]+[old.UNIT/name for name in units()];require(not any(os.path.lexists(p) for p in paths),'fixture destination occupied')
 search=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(search,'unit paths unavailable')
 for name in units():
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','fixture unit occupied');stem=name.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
  for base in map(pathlib.Path,search):
   for p in [base/name,base/(name+'.d'),base/'service.d']+[base/(prefix+'.service.d') for prefix in prefixes]:require(not os.path.lexists(p),'unit collision')
 return {'root':str(ROOT),'data_owner':[2004,2004,448],'config_sha256':sha(CONF),'anchor_sha256':sha(ANCHOR_SOURCE),'probe_sha256':sha(PROBE_SOURCE),'units':{n:sha(v) for n,v in units().items()},'restate':restate,'old':old.old_snapshot(),'scope':'create-only files and inactive units; no service start, network change or live data'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,canonical(approved)+b'\n',0o600)
 os.mkdir(ROOT,0o700);os.chmod(ROOT,0o711);os.mkdir(DATA,0o700);os.chmod(DATA,0o700);os.chown(DATA,2004,2004)
 for p,u,g,m in [(ROOT,0,0,0o711),(DATA,2004,2004,0o700)]:old.directory(p,u,g,m)
 old.syncdir(ROOT);old.syncdir(ROOT.parent);old.store(CONFIG,CONF,0o644);old.store(ANCHOR,ANCHOR_SOURCE,0o755);old.store(PROBE,PROBE_SOURCE,0o755)
 for name,data in units().items():old.store(old.UNIT/name,data,0o644)
 old.ctl('daemon-reload')
 for name in units():
  p=dict(line.split('=',1) for line in old.ctl('show',name,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,Job','--no-pager').splitlines())
  require(p.get('LoadState')=='loaded' and p.get('ActiveState')=='inactive' and p.get('MainPID')=='0' and p.get('Job','')=='' and p.get('Names')==name and p.get('FragmentPath')==str(old.UNIT/name) and p.get('DropInPaths','')=='','fixture unit identity mismatch')
 require(old.old_snapshot()==approved['old'],'existing factory changed')
 result={'installed':True,'started':False,'network_changed':False,'production_data_used':False};old.store(DONE,canonical(result)+b'\n',0o600);return result
