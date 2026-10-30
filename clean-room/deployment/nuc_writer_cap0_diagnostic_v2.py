"""Historical closed-generation writer initialization diagnostic; never authority."""
import hashlib,json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGG';NAME='sfactory-writer-cap0-diagnostic-v2-20261030.service'
START=old.ETC/'writer-cap0-diagnostic-v2-started.json';DONE=old.ETC/'writer-cap0-diagnostic-v2-complete.json';PKG=old.PREFIX/'relay'
CODE=r'''import ctypes,errno,json,os,pathlib,socket,stat,sys
sys.path.insert(0,'/usr/local/libexec/software-factory-goose/relay')
import nuc_root_writer_service as w
G='01M65RMR3F04YB1B016EBBSXGG';prefix=w.ETC+'/relay-catalog/'+G;paths={'scope':prefix+'.scope.json','provider':prefix+'.provider.json','catalog':w.ETC+'/launch-catalog/'+G+'.json','consumed':w.ROOT+'/'+G+'.launch-consumed'}
results={};cache={};fds=[]
def stage(name,fn):
 try:cache[name]=fn();results[name]={'status':'pass'}
 except OSError as e:results[name]={'status':'os_error','errno':e.errno if e.errno in (1,2,9,13,20,40,95) else 'other'}
 except Exception:results[name]={'status':'denied'}
def security():
 fields=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
 if os.getuid()!=0 or os.geteuid()!=0 or any(int(fields[n].strip(),16)!=0 for n in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')) or fields['NoNewPrivs'].strip()!='1':raise RuntimeError('bad process')
def parent_dirs():
 for path in paths.values():
  for parent in pathlib.Path(path).parents:
   fd=w.safe_dir(str(parent));os.close(fd)
def scope():
 f={}
 for name,path in paths.items():f[name]=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);fds.append(f[name])
 return w.load_root_scope(f['scope'],f['consumed'],f['catalog'],f['provider'])
def task():return json.loads(w.root_file(w.ETC+'/tasks/'+G+'.json'),object_pairs_hook=w.no_duplicates)
def handoff():
 for parent in (w.HANDOFF,w.HANDOFF+'/'+G):fd=w.safe_dir(parent,mode=0o700);os.close(fd)
 d={}
 for name,owner in (('input',0),('output',2001),('candidate',2001)):
  fd=w.safe_dir(w.HANDOFF+'/'+G+'/'+name,owner,owner,0o755);fds.append(fd);d[name+'_dir']=fd
 return d
def writer_binding():
 fd=os.open(prefix+'.writer.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);fds.append(fd);return w.load_writer_binding(fd,cache['scope_binding'][0],cache['task'],cache['handoff_directories'])
def listener_metadata():
 parent=w.safe_dir('/run/software-factory-goose/writer',0,2000,0o710);os.close(parent);p='/run/software-factory-goose/writer/'+G+'.sock';s=os.stat(p,follow_symlinks=False)
 if not stat.S_ISSOCK(s.st_mode) or (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)!=(0,2000,0o660,1):raise RuntimeError('socket mismatch')
 try:os.getxattr(p,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:
  if e.errno!=errno.ENODATA:raise
 else:raise RuntimeError('socket ACL')
stage('process_protection',security);stage('parent_directories',parent_dirs);stage('scope_binding',scope);stage('task',task);stage('handoff_directories',handoff)
if all(k in cache for k in ('scope_binding','task','handoff_directories')):stage('writer_binding',writer_binding)
if 'writer_binding' in cache:stage('writer_provenance',lambda:w.verify_writer_provenance(cache['writer_binding']))
stage('state_directory',lambda:os.close(w.safe_dir(w.ROOT,mode=0o700)));stage('cgroup_directory',lambda:os.close(w.safe_dir(w.CG+'/sfactory'+G.lower()+'.slice')));stage('listener_metadata',listener_metadata)
def cgroup_filesystem():
 fd=os.open(w.CG+'/sfactory'+G.lower()+'.slice',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);buf=ctypes.create_string_buffer(256);libc=ctypes.CDLL(None,use_errno=True)
  if libc.fstatfs(fd,ctypes.byref(buf))!=0:raise OSError(ctypes.get_errno(),'fstatfs')
  if ctypes.c_long.from_buffer(buf).value!=0x63677270 or st.st_uid!=0 or 'task' not in cache or (st.st_dev,st.st_ino)!=(cache['task']['cgroup_dev'],cache['task']['cgroup_ino']):raise RuntimeError('cgroup identity mismatch')
 finally:os.close(fd)
stage('cgroup2_identity',cgroup_filesystem)
def cgroup_acl_direct():
 fd=os.open(w.CG+'/sfactory'+G.lower()+'.slice',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.getxattr(fd,'system.posix_acl_access')
 finally:os.close(fd)
stage('cgroup_acl_direct',cgroup_acl_direct)
if 'scope_binding' in cache:stage('provider_inspect_namespace',lambda:w.inspect_bifrost(cache['scope_binding'][1]))
for fd in fds:os.close(fd)
print(json.dumps({'checks':results,'historical_only':True,'grant_requested':False,'provider_http':False,'worker_started':False},sort_keys=True),flush=True)
'''
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(x) for x in (START,DONE)) and old.ctl('show',NAME,'-p','LoadState','--value')=='not-found','diagnostic state occupied')
 pkg=json.loads(old.read(old.ETC/'relay-package.json',0o600));require(isinstance(pkg.get('files'),dict) and len(pkg['files'])>=13,'package unavailable')
 for n,d in pkg['files'].items():
  require(isinstance(n,str) and re.fullmatch(r'[A-Za-z0-9_.-]+',n) and n not in ('.','..') and isinstance(d,str) and re.fullmatch(r'[0-9a-f]{64}',d),'invalid package entry');old.read(PKG/n,0o444,d,1_000_000)
 return {'generation':G,'unit':NAME,'program_sha256':hashlib.sha256(CODE.encode()).hexdigest(),'package_sha256':hashlib.sha256(old.read(old.ETC/'relay-package.json',0o600)).hexdigest(),'scope':'historical read-only initialization; no authorization, grant, provider HTTP or worker'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 args=['/usr/bin/systemd-run','--unit='+NAME,'--wait','--pipe','--quiet','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=RestrictAddressFamilies=AF_UNIX','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=ReadWritePaths=/var/lib/software-factory-goose/stop /var/lib/software-factory-goose/handoff/'+G+'/input','--property=MemoryMax=256M','--property=TasksMax=32','--property=CPUQuota=100%','--property=LimitCORE=0','--property=RuntimeMaxSec=90s','/usr/bin/python3','-I','-B','-c',CODE]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=105,check=False);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'diagnostic outcome unknown')
 result=json.loads(p.stdout);require(result.get('historical_only') is True and result.get('grant_requested') is False and result.get('provider_http') is False and result.get('worker_started') is False,'unexpected diagnostic result')
 old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
