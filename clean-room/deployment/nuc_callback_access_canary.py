"""Task-owned actual UID callback-parent access canary; no existing sockets modified."""
import json,os,pathlib,socket,stat,subprocess,uuid
import nuc_grant_sidecar_install as old
ROOT=pathlib.Path('/tmp');PARENT=ROOT/'sfactory-callback-access-20261030';START=old.ETC/'callback-access-canary-started.json';DONE=old.ETC/'callback-access-canary-complete.json'
UNITS={'sfgoose-control':'sfactory-callback-access-control-20261030.service','sfgoose-worker':'sfactory-callback-access-worker-20261030.service'}
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (PARENT,START,DONE)),'root or clean canary state unavailable')
 for name in UNITS.values():require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','canary unit occupied')
 return {'parent':str(PARENT),'units':UNITS,'scope':'new temporary root-owned 0710 socket parent; UID 2000 validation and mutation denial; UID 2001 child stat/connect denial','no_existing_socket_modified':True}
def role(user,code):
 name=UNITS[user]
 p=subprocess.run(['/usr/bin/systemd-run','--unit='+name,'--wait','--pipe','--quiet','--property=User='+user,'--property=Group='+user,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=20s','/usr/bin/python3','-I','-B','-c',code],env=old.ENV,capture_output=True,timeout=30,check=False)
 require(p.returncode==0 and len(p.stdout)<4096 and len(p.stderr)<4096,'role check failed');return json.loads(p.stdout)
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600);parent=PARENT;os.mkdir(parent,0o710);os.chmod(parent,0o710);os.chown(parent,0,2000);listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
 try:
  path=parent/'relay.sock';listener.bind(str(path));os.chown(path,0,2001);os.chmod(path,0o660);listener.listen(1)
  st=os.lstat(parent);require((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(0,2000,0o710),'parent identity mismatch')
  control='''import json,os,pathlib,socket,stat\np=pathlib.Path(%r);d=os.open(p,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW);s=os.stat("relay.sock",dir_fd=d,follow_symlinks=False);assert stat.S_ISSOCK(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(0,2001,0o660)\nfor name,fn in [("unlink",lambda:os.unlink("relay.sock",dir_fd=d)),("create",lambda:os.open("evil",os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600,dir_fd=d)),("rename",lambda:os.rename("relay.sock","other",src_dir_fd=d,dst_dir_fd=d))]:\n try:fn()\n except PermissionError:continue\n raise RuntimeError(name+" allowed")\nprint(json.dumps({"validated":True,"mutations_denied":True}))'''%str(parent)
  worker='''import json,os,socket\np=%r\nfor fn in (lambda:os.stat(p),lambda:socket.socket(socket.AF_UNIX,socket.SOCK_STREAM).connect(p)):\n try:fn()\n except PermissionError:continue\n raise RuntimeError("worker access allowed")\nprint(json.dumps({"stat_denied":True,"connect_denied":True}))'''%str(path)
  a=role('sfgoose-control',control);b=role('sfgoose-worker',worker);require(a=={'validated':True,'mutations_denied':True} and b=={'stat_denied':True,'connect_denied':True},'role result mismatch')
  result={'control':a,'worker':b,'existing_socket_modified':False}
 finally:
  listener.close();os.unlink(parent/'relay.sock');os.rmdir(parent)
 old.syncdir(ROOT);old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
