"""Create one fresh control-owned hello baseline; never touch prior repositories."""
import errno,hashlib,json,os,pathlib,pwd,re,stat,subprocess
PARENT=pathlib.Path('/var/lib/software-factory-goose/repositories')
REPO=PARENT/'hello-int-loop-20261030'
INTENT=pathlib.Path('/etc/software-factory-goose/real-repo-started.json')
DONE=pathlib.Path('/etc/software-factory-goose/real-repo-complete.json')
UNIT='software-factory-goose-real-repo-bootstrap.service'
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C'}
README='Disposable software-factory Goose INT-LOOP task.\n'
AGENTS='Implement only hello.py and test_hello.py. Use Python 3 standard library only. Preserve README.md, AGENTS.md, and requirements.md. Do not use network, third-party dependencies, or external files.\n'
REQUIREMENTS='''Build a dependency-free Python 3 CLI in hello.py. Running python3 hello.py prints hello world followed by one newline. One positional name replaces world, preserving spaces and Unicode. Optional --uppercase may occur before or after the name and uppercases the whole greeting. More than one name or any unknown option must exit 2, print no stdout, and explain usage on stderr. Add unittest tests in test_hello.py. Only these two files may be added; do not modify the baseline README. No network, third-party dependencies, or external files are needed.\n'''
FILES={'README.md':README,'AGENTS.md':AGENTS,'requirements.md':REQUIREMENTS}
CODE=r'''import json,os,pathlib,subprocess,sys
root=pathlib.Path('/var/lib/software-factory-goose/repositories/hello-int-loop-20261030')
if os.geteuid()!=2000 or sorted(p.name for p in root.iterdir())!=['AGENTS.md','README.md','requirements.md']:raise RuntimeError('repository bootstrap scope')
env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_AUTHOR_NAME':'Software Factory','GIT_AUTHOR_EMAIL':'factory@localhost.invalid','GIT_COMMITTER_NAME':'Software Factory','GIT_COMMITTER_EMAIL':'factory@localhost.invalid','GIT_AUTHOR_DATE':'2026-10-30T00:00:00+00:00','GIT_COMMITTER_DATE':'2026-10-30T00:00:00+00:00'}
def git(*args):
 p=subprocess.run(['/usr/bin/git','-C',str(root),*args],env=env,capture_output=True,timeout=15,check=True)
 if len(p.stdout)>8192 or len(p.stderr)>8192:raise RuntimeError('git output limit')
 return p.stdout.decode().strip()
git('init','-b','main');git('add','--','README.md','AGENTS.md','requirements.md');git('commit','-m','Establish hello task baseline');sha=git('rev-parse','HEAD')
if len(sha)!=40 or git('status','--porcelain') or git('ls-tree','-r','--name-only','HEAD').splitlines()!=['AGENTS.md','README.md','requirements.md']:raise RuntimeError('baseline mismatch')
print(json.dumps({'baseline':sha}))
'''
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def safe_dir(path,uid,mode):
 s=os.lstat(path);require(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode) and s.st_uid==uid and s.st_gid==uid and stat.S_IMODE(s.st_mode)==mode,'directory scope mismatch')
 for a in ('system.posix_acl_access','system.posix_acl_default'):
  try:os.getxattr(path,a,follow_symlinks=False)
  except OSError as e:require(e.errno==errno.ENODATA,'ACL unavailable')
  else:raise RuntimeError('ACL forbidden')
def plan():
 require(os.geteuid()==0 and pwd.getpwnam('sfgoose-control').pw_uid==2000,'control identity unavailable')
 for path,mode in [('/',0o755),('/var',0o755),('/var/lib',0o755),('/var/lib/software-factory-goose',0o711),('/etc',0o755),('/etc/software-factory-goose',0o711)]:safe_dir(pathlib.Path(path),0,mode)
 require(not any(os.path.lexists(p) for p in (PARENT,REPO,INTENT,DONE)),'repository scope occupied')
 p=subprocess.run(['/usr/bin/systemctl','show',UNIT,'-p','LoadState','--value'],env=ENV,capture_output=True,timeout=10,check=True);require(p.stdout.strip()==b'not-found','bootstrap unit occupied')
 return {'repo':str(REPO),'owner_uid':2000,'files':{k:hashlib.sha256(v.encode()).hexdigest() for k,v in FILES.items()},'bootstrap_sha256':hashlib.sha256(CODE.encode()).hexdigest(),'scope':'create fresh repository only; no registration, launch or provider'}
def store(path,data,mode):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 try:
  os.fchmod(fd,mode);view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);os.fsync(fd);os.close(fd)
def apply(approved):
 require(plan()==approved,'repository plan changed')
 store(INTENT,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 os.mkdir(PARENT,0o711);os.chmod(PARENT,0o711);safe_dir(PARENT,0,0o711)
 fd=os.open(PARENT.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);os.fsync(fd);os.close(fd)
 os.mkdir(REPO,0o700);os.chmod(REPO,0o700);os.chown(REPO,2000,2000);safe_dir(REPO,2000,0o700)
 fd=os.open(PARENT,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);os.fsync(fd);os.close(fd)
 for name,value in FILES.items():
  path=REPO/name;store(path,value.encode(),0o600);os.chown(path,2000,2000)
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);os.fsync(fd);os.close(fd)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--collect','--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=MemoryMax=128M','--property=TasksMax=32','--property=CPUQuota=50%','--property=RuntimeMaxSec=30s','/usr/bin/python3','-I','-B','-c',CODE]
 p=subprocess.run(args,env=ENV,capture_output=True,timeout=40,check=False);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'bootstrap unknown; preserve intent')
 result=json.loads(p.stdout);require(set(result)=={'baseline'} and re.fullmatch(r'[0-9a-f]{40}',result['baseline']) is not None,'baseline unknown')
 safe_dir(PARENT,0,0o711);safe_dir(REPO,2000,0o700)
 for name,text in FILES.items():
  path=REPO/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   s=os.fstat(fd);data=os.read(fd,8193);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)==(2000,2000,0o600,1) and data==text.encode(),'baseline file changed')
  finally:os.close(fd)
 result.update(repo=str(REPO),files=approved['files'],no_provider=True)
 store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
