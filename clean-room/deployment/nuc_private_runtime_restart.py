#!/usr/bin/env python3
"""One-shot exact private-runtime restart for the retained canary; no other service restart."""
import errno,hashlib,json,os,pathlib,stat,subprocess,sys
ETC=pathlib.Path('/etc/software-factory-goose');RUN=pathlib.Path('/run/software-factory-goose')
UNIT=pathlib.Path('/etc/systemd/system');PREFIX='software-factory-goose-private-'
INTENT=ETC/'private-runtime-restart-started.json';DONE=ETC/'private-runtime-restart-complete.json'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LANG':'C'}
EXPECTED={
 '/etc/software-factory-goose/runtime.json':('53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6',0o644),
 '/etc/software-factory-goose/private-genesis.json':('395151c9c7ef720740288fc23234117e6473667baf71997e949d3db4f61cea75',0o644),
 '/etc/software-factory-goose/private-bootstrap-complete':('905c9966bb6cbdf8a8441beed4a2c6c8f51a5f1b32e32856ff963b440478beb1',0o644),
 '/usr/local/libexec/software-factory-goose/private-runtime':('9ca260b3aebcfcd082ac6521825b20a4312b2ec991ab03a957ea89ffa6288082',0o755),
 '/etc/systemd/system/software-factory-goose-private-runtime.service':('5fe9af9180d08242e40614a5b1994ea3b4933bc92694b28abf8d48fcc69e3ebe',0o644),
}
SOCKETS={'intake.sock':(25,2600598,1000),'worker.sock':(25,2600602,2001)}
SUPPORT={'host-net.service':(418527,64*1024**2,16,50),'net.service':(418529,64*1024**2,16,50),'postgres.service':(418536,1024**3,128,200),'restate.service':(418551,4*1024**3,256,200)}
TARGET='runtime.service';TARGET_PID=418558

def require(x,message):
 if not x:raise RuntimeError(message)
def noacl(path,directory=False,follow=False):
 for attr in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(path,attr,follow_symlinks=follow)
  except OSError as e:require(e.errno==errno.ENODATA,'ACL unavailable')
  else:raise RuntimeError('ACL forbidden')
def check_ancestor(path,mode):
 s=os.lstat(path);require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode,'unsafe root ancestor');noacl(path,True)
def file_info(path,digest,mode):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode and s.st_size<=100_000_000,'file identity mismatch')
  try:os.getxattr(fd,'system.posix_acl_access')
  except OSError as e:require(e.errno==errno.ENODATA,'file ACL unavailable')
  else:raise RuntimeError('file ACL forbidden')
  h=hashlib.sha256();data=bytearray() if s.st_size<=4096 else None;total=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   total+=len(b);require(total<=s.st_size,'file grew');h.update(b)
   if data is not None:data.extend(b)
  require(total==s.st_size and h.hexdigest()==digest,'file digest mismatch')
  return {'dev':s.st_dev,'ino':s.st_ino,'sha256':digest},bytes(data) if data is not None else None
 finally:os.close(fd)
def command(args,timeout=15):
 p=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
 require(p.returncode==0 and len(p.stdout)<=16384 and len(p.stderr)<=16384,'systemd outcome unavailable')
 return p.stdout.decode().strip()
def service(name,memory,pids,cpu):
 full=PREFIX+name;output=command(['/usr/bin/systemctl','show',full,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,ControlGroup','--no-pager'])
 values=dict(line.split('=',1) for line in output.splitlines())
 require(values.get('LoadState')=='loaded' and values.get('ActiveState')=='active' and values.get('Names')==full and values.get('FragmentPath')==str(UNIT/full) and values.get('DropInPaths')==str(UNIT/(full+'.d')/'50-resources.conf'),'loaded service mismatch')
 pid=int(values['MainPID']);require(pid>1,'service PID missing');group='/system.slice/'+full;require(values.get('ControlGroup')==group,'service cgroup mismatch')
 path=pathlib.Path('/sys/fs/cgroup'+group);s=os.stat(path);require(s.st_uid==0,'cgroup owner mismatch');ident=(s.st_dev,s.st_ino)
 quota=(path/'cpu.max').read_text().split();require((path/'memory.max').read_text().strip()==str(memory) and (path/'pids.max').read_text().strip()==str(pids) and len(quota)==2 and all(x.isdigit() for x in quota) and int(quota[0])*100==int(quota[1])*cpu,'live cgroup resource mismatch')
 s=os.stat(path);require((s.st_dev,s.st_ino)==ident,'cgroup changed')
 return {'pid':pid,'cgroup_dev':s.st_dev,'cgroup_ino':s.st_ino}
def snapshot(expected_pid=None):
 require(os.geteuid()==0,'root required')
 for p,mode in [('/',0o755),('/etc',0o755),('/etc/software-factory-goose',0o711),('/etc/systemd',0o755),('/etc/systemd/system',0o755),('/run',0o755),('/run/software-factory-goose',0o755),('/usr',0o755),('/usr/local',0o755),('/usr/local/libexec',0o755),('/usr/local/libexec/software-factory-goose',0o755)]:check_ancestor(p,mode)
 files={};contents={}
 for path,(digest,mode) in EXPECTED.items():files[path],contents[path]=file_info(path,digest,mode)
 cfg=json.loads(contents[str(ETC/'runtime.json')]);genesis=json.loads(contents[str(ETC/'private-genesis.json')])
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();require(cfg['boot_id']==boot and genesis['boot_id']==boot and genesis['postgres_system_id']=='7702303394074795435' and (genesis['pgdata_dev'],genesis['pgdata_ino'])==(66306,19138550),'bootstrap/boot identity mismatch')
 sockets={}
 for name,(dev,ino,gid) in SOCKETS.items():
  path=RUN/name;s=os.lstat(path);require(stat.S_ISSOCK(s.st_mode) and (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(dev,ino,0,gid,0o660),'socket mismatch');noacl(path)
  sockets[name]={'dev':dev,'ino':ino,'gid':gid}
 support={}
 for name,(pid,memory,pids,cpu) in SUPPORT.items():
  value=service(name,memory,pids,cpu);require(value['pid']==pid,'support PID changed');support[name]=value
 target=service(TARGET,512*1024**2,128,100)
 if expected_pid is not None:require(target['pid']==expected_pid,'runtime PID mismatch')
 return {'boot_id':boot,'files':files,'sockets':sockets,'support':support,'runtime':target,'pg_system_id':'7702303394074795435'}
def store(path,value):
 data=json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  os.fchmod(fd,0o600);view=memoryview(data)
  while view:
   n=os.write(fd,view);require(n>0,'short receipt');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def plan():
 require(not os.path.lexists(INTENT) and not os.path.lexists(DONE),'restart already attempted')
 return {'format':1,'before':snapshot(TARGET_PID),'scope':'exact private runtime only; no registration or shared service restart'}
def apply(approved):
 require(plan()==approved,'reviewed restart plan changed')
 store(INTENT,approved)
 # Timeout or failed response is unknown; retain intent and never retry here.
 command(['/usr/bin/systemctl','restart',PREFIX+TARGET],timeout=45)
 after=snapshot()
 require(after['runtime']['pid']!=approved['before']['runtime']['pid'],'runtime PID did not change')
 for key in ('boot_id','files','sockets','support','pg_system_id'):require(after[key]==approved['before'][key],'post-restart binding changed')
 store(DONE,{'format':1,'before':approved['before']['runtime'],'after':after['runtime']})
 print(json.dumps({'private_runtime_restarted':True,'old_pid':approved['before']['runtime']['pid'],'new_pid':after['runtime']['pid']},sort_keys=True))
if __name__=='__main__':
 if sys.argv==[sys.argv[0],'--plan']:print(json.dumps(plan(),sort_keys=True,indent=2))
 elif sys.argv==[sys.argv[0],'--apply']:
  raw=sys.stdin.buffer.read(1_000_001);require(len(raw)<=1_000_000,'plan too large');apply(json.loads(raw))
 else:raise SystemExit('expected --plan or --apply')
