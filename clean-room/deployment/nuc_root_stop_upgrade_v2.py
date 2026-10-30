#!/usr/bin/env python3
"""Review-only V1-to-V2 binary upgrade. No unit activation or automatic rollback."""
import hashlib,json,os,pathlib,stat,subprocess,sys
BASE=pathlib.Path('/usr/local/libexec/software-factory-goose')
STATE=pathlib.Path('/var/lib/software-factory-goose/stop')
SYSTEM=pathlib.Path('/etc/systemd/system')
INSTALLED=BASE/'sfactory_root_stop'
SOURCE=pathlib.Path('/tmp/sfactory-stop-build-_10otcq2/install-candidate/sfactory_root_stop_v2')
BACKUP=BASE/'sfactory_root_stop_v1_4369a471'
TEMP=BASE/'sfactory_root_stop_v2_pending'
INTENT=STATE/'root-stop-v2-upgrade-intent.json'
RECEIPT=STATE/'root-stop-v2-upgrade-receipt.json'
V1='4369a4712c2563ef8516b19053c2821a7246c928516ca3d03e9a2530e00348f1'
V2='99236f262d181442e395a9f706e99856027fab7f069bcb6fefb6950b0c324443'
FILES={SYSTEM/'software-factory-goose-root-stop.service':'05e4d2269d42696cbf2813099e5a75be5ea019c613020672b0964fac669c4f7f',SYSTEM/'software-factory-goose-root-stop.socket':'e04cc83d65bd2f7712d4c63f46c17ec3b90017e4a514c15499e01f698c57bdba',SYSTEM/'software-factory-goose-root-stop.service.d/10-no-docker.conf':'f9385702a27ae06a58a4b61fbbe6bf6c679d6271074642f2e30176595b08b047'}

def trusted_dir(path):
 s=path.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_mode&0o022:raise RuntimeError('untrusted directory: '+str(path))

def digest(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def write_new(path,data,mode):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
 with os.fdopen(fd,'wb') as f:
  os.fchmod(f.fileno(),mode);s=os.fstat(f.fileno())
  if s.st_uid!=0 or s.st_gid!=0:raise RuntimeError('created file owner mismatch')
  f.write(data);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def read_pinned(path,uid,sha,mode=None):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or s.st_nlink!=1 or s.st_size>64*1024*1024 or (mode is not None and (s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=mode)):raise RuntimeError('file metadata mismatch: '+str(path))
  data=f.read(64*1024*1024+1)
  if hashlib.sha256(data).hexdigest()!=sha:raise RuntimeError('file digest mismatch: '+str(path))
  return data,(s.st_dev,s.st_ino)

def inactive():
 for unit in ('software-factory-goose-root-stop.socket','software-factory-goose-root-stop.service'):
  p=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=ActiveState','--value'],capture_output=True,text=True,timeout=10,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0'})
  if p.returncode or p.stdout.strip() not in ('inactive','failed'):raise RuntimeError('unit not inactive: '+unit)
 if pathlib.Path('/run/software-factory-goose/root-stop.sock').exists():raise RuntimeError('socket remains')

def guard():
 env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0'}
 def run(*args):
  p=subprocess.run(args,capture_output=True,text=True,timeout=15,env=env)
  if p.returncode:raise RuntimeError('guard query failed')
  return p.stdout.strip()
 docker=('/usr/bin/docker','--host','unix:///run/docker.sock')
 info=json.loads(run(*docker,'info','--format','{{json .}}'))
 pid=run('/usr/bin/systemctl','show','docker.service','-p','MainPID','--value')
 commit=run(*docker,'version','--format','{{.Server.GitCommit}}')
 ident='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062'
 original=json.loads(run(*docker,'inspect',ident))[0]
 if info.get('ID')!='56d25a60-5f64-4212-b904-e750067ac6a5' or pid!='2145' or commit!='3ce5872' or original['Id']!=ident or original['Name']!='/sf-owner-224a71d2db764249aa6cade3c1b39c80' or original['State']['Status']!='created' or original['State']['Pid']!=0:raise RuntimeError('original guard changed')

def plan():
 for p in (pathlib.Path('/'),pathlib.Path('/usr'),pathlib.Path('/usr/local'),pathlib.Path('/usr/local/libexec'),BASE,pathlib.Path('/var'),pathlib.Path('/var/lib'),STATE.parent,STATE,pathlib.Path('/etc'),pathlib.Path('/etc/systemd'),SYSTEM,SYSTEM/'software-factory-goose-root-stop.service.d'):trusted_dir(p)
 inactive();guard()
 if any(p.exists() or p.is_symlink() for p in (BACKUP,TEMP,INTENT,RECEIPT)):raise RuntimeError('prior upgrade artifact exists; retain')
 old,identity=read_pinned(INSTALLED,0,V1,0o755);new,_=read_pinned(SOURCE,1000,V2)
 for p,h in FILES.items():read_pinned(p,0,h,0o644)
 for p in (STATE/'root-stop-mask-intent.json',STATE/'root-stop-mask-receipt.json'):
  s=p.lstat()
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise RuntimeError('mask record metadata mismatch')
 mask_sha=FILES[SYSTEM/'software-factory-goose-root-stop.service.d/10-no-docker.conf']
 if json.loads((STATE/'root-stop-mask-intent.json').read_text())!={'sha256':mask_sha} or json.loads((STATE/'root-stop-mask-receipt.json').read_text())!={'sha256':mask_sha,'status':'installed'}:raise RuntimeError('mask record contents mismatch')
 spec={'version':2,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'old_sha256':V1,'new_sha256':V2,'old_device_inode':identity,'units':{str(p):h for p,h in FILES.items()},'backup':str(BACKUP),'temp':str(TEMP),'activation':'none'}
 return spec,old,new

def main():
 if len(sys.argv) not in (2,3) or sys.argv[1] not in ('plan','apply') or os.geteuid()!=0:raise RuntimeError('root and plan or apply PLAN_HASH required')
 spec,old,new=plan();h=digest(spec)
 if sys.argv[1]=='plan':print(json.dumps({'plan':spec,'sha256':h},sort_keys=True));return
 if len(sys.argv)!=3 or sys.argv[2]!=h:raise RuntimeError('exact plan hash required')
 write_new(INTENT,json.dumps({'plan_sha256':h,'plan':spec},sort_keys=True).encode(),0o600)
 write_new(BACKUP,old,0o755);write_new(TEMP,new,0o755)
 inactive();guard()
 _,identity=read_pinned(INSTALLED,0,V1,0o755)
 if list(identity)!=list(spec['old_device_inode']):raise RuntimeError('old inode changed')
 for p,sha in FILES.items():read_pinned(p,0,sha,0o644)
 read_pinned(BACKUP,0,V1,0o755);read_pinned(TEMP,0,V2,0o755)
 os.replace(TEMP,INSTALLED)
 fd=os.open(BASE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 read_pinned(INSTALLED,0,V2,0o755);read_pinned(BACKUP,0,V1,0o755)
 write_new(RECEIPT,json.dumps({'plan_sha256':h,'status':'installed_not_activated'},sort_keys=True).encode(),0o600)
 print(json.dumps({'status':'installed_not_activated','plan_sha256':h},sort_keys=True))
if __name__=='__main__':main()
