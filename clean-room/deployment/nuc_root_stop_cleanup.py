#!/usr/bin/env python3
"""Review-only exact cleanup of the failed native root-stop canary; no retry."""
import hashlib,json,os,pathlib,re,stat,subprocess,sys,time,uuid
T='01M65B8JZ3RSJZ8NQ03HRX9DWV'; S='sfactory'+T.lower()+'.slice'; A='sfactory'+T.lower()+'-anchor.service'
ROOT=pathlib.Path('/etc/software-factory-goose/tasks'); STATE=pathlib.Path('/var/lib/software-factory-goose/stop'); CG=pathlib.Path('/sys/fs/cgroup')/S
SERVICE='software-factory-goose-root-stop.service'; SOCKUNIT='software-factory-goose-root-stop.socket'; SOCK=pathlib.Path('/run/software-factory-goose/root-stop.sock')
BINARY=pathlib.Path('/usr/local/libexec/software-factory-goose/sfactory_root_stop'); BIN_SHA='4369a4712c2563ef8516b19053c2821a7246c928516ca3d03e9a2530e00348f1'
MASK_SHA='f9385702a27ae06a58a4b61fbbe6bf6c679d6271074642f2e30176595b08b047'
UNIT_SHA={'/etc/systemd/system/software-factory-goose-root-stop.service':'05e4d2269d42696cbf2813099e5a75be5ea019c613020672b0964fac669c4f7f','/etc/systemd/system/software-factory-goose-root-stop.socket':'e04cc83d65bd2f7712d4c63f46c17ec3b90017e4a514c15499e01f698c57bdba','/etc/systemd/system/software-factory-goose-root-stop.service.d/10-no-docker.conf':MASK_SHA}
def run(*a,check=True,timeout=15):
 p=subprocess.run(a,capture_output=True,text=True,check=False,timeout=timeout,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0'})
 if check and p.returncode:raise RuntimeError('fixed command failed: '+pathlib.Path(a[0]).name)
 return p
def system(*a,check=True):return run('/usr/bin/systemctl',*a,check=check)
def protected(path,mode):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=mode or s.st_size>10*1024*1024:raise RuntimeError('untrusted protected file')
  return f.read()
def store(path,obj):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(obj,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def guard():
 d=['/usr/bin/docker','--host','unix:///run/docker.sock'];x=json.loads(run(*d,'info','--format','{{json .}}').stdout);pid=system('show','docker.service','-p','MainPID','--value').stdout.strip();commit=run(*d,'version','--format','{{.Server.GitCommit}}').stdout.strip();o=json.loads(run(*d,'inspect','04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062').stdout)[0]
 if x.get('ID')!='56d25a60-5f64-4212-b904-e750067ac6a5' or pid!='2145' or commit!='3ce5872' or o['Id']!='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062' or o['Name']!='/sf-owner-224a71d2db764249aa6cade3c1b39c80' or o['State']['Status']!='created' or o['State']['Pid']!=0:raise RuntimeError('guard changed')
def peer(op):
 code="import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(8);s.connect('/run/software-factory-goose/root-stop.sock');s.sendall(sys.argv[1].encode());s.shutdown(socket.SHUT_WR);b=b''\nwhile True:\n x=s.recv(4096)\n if not x:break\n b+=x\n if len(b)>4096:raise RuntimeError('oversized')\nprint(b.decode())"
 unit='sfactory-cleanup-peer-'+uuid.uuid4().hex+'.service'
 if system('show',unit,'-p','LoadState','--value',check=False).stdout.strip() not in ('','not-found'):raise RuntimeError('peer collision')
 p=run('/usr/bin/systemd-run','--unit='+unit,'--collect','--wait','--pipe','--property=User=sfgoose-brake','--property=Group=sfgoose-brake','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=RuntimeMaxSec=15s','/usr/bin/python3','-I','-B','-c',code,json.dumps({'operation':op,'target':T},separators=(',',':')),timeout=20)
 return json.loads(p.stdout)
def events():return dict(line.split() for line in (CG/'cgroup.events').read_text().splitlines())
def manager_exec_matches(value,pid):
 path='/usr/local/libexec/software-factory-goose/sfactory_root_stop'
 return (pid>0 and value.count('{ path=')==1 and
         ('{ path='+path+' ; argv[]='+path+' ; ignore_errors=no ;') in value and
         re.search(r'\bpid='+str(pid)+r'\s*;\s*code=\(null\)\s*;\s*status=0/0\s*\}',value) is not None)
def main():
 if sys.argv!=[sys.argv[0],'--run'] or os.geteuid()!=0:raise RuntimeError('root and explicit cleanup required')
 if hashlib.sha256(protected(BINARY,0o755)).hexdigest()!=BIN_SHA:raise RuntimeError('binary changed')
 for name,sha in UNIT_SHA.items():
  if hashlib.sha256(protected(pathlib.Path(name),0o644)).hexdigest()!=sha:raise RuntimeError('unit or mask changed')
 mask_i=json.loads(protected(STATE/'root-stop-mask-intent.json',0o600));mask_r=json.loads(protected(STATE/'root-stop-mask-receipt.json',0o600))
 if mask_i!={'sha256':MASK_SHA} or mask_r!={'sha256':MASK_SHA,'status':'installed'}:raise RuntimeError('mask record mismatch')
 intent=json.loads(protected(STATE/(T+'.canary-intent.json'),0o600));cat=json.loads(protected(ROOT/(T+'.json'),0o600));boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 if set(intent)!={'target_id','task_id','slice','unit','operation'} or intent.get('target_id')!=T or intent.get('slice')!=S or intent.get('unit')!=A or intent.get('operation')!='native-sleeper-stop' or not re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',intent.get('task_id','')) or set(cat)!={'schema','target_id','task_id','generation','boot_id','cgroup_dev','cgroup_ino'} or cat.get('schema')!=1 or cat.get('target_id')!=T or cat.get('generation')!=T or cat.get('task_id')!=intent.get('task_id') or cat.get('boot_id')!=boot:raise RuntimeError('old canary record mismatch')
 if CG.is_symlink() or CG.resolve(strict=True)!=CG:raise RuntimeError('cgroup identity unresolved')
 c=CG.stat()
 if c.st_dev!=cat.get('cgroup_dev') or c.st_ino!=cat.get('cgroup_ino') or events().get('populated')!='0':raise RuntimeError('old cgroup not empty')
 props={}
 for key in ('Description','ActiveState','Result','ControlGroup'):props[key]=system('show',A,'-p',key,'--value').stdout.strip()
 if props!={'Description':A,'ActiveState':'failed','Result':'timeout','ControlGroup':''}:raise RuntimeError('old unit state mismatch')
 if any(p.name!=A for p in CG.iterdir() if p.is_dir()):raise RuntimeError('foreign child present')
 sock=SOCK.lstat()
 if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid!=0 or sock.st_gid!=2003 or stat.S_IMODE(sock.st_mode)!=0o660:raise RuntimeError('socket identity mismatch')
 service_pid=int(system('show',SERVICE,'-p','MainPID','--value').stdout.strip())
 exec_start=system('show',SERVICE,'-p','ExecStart','--value').stdout
 if system('is-active','--quiet',SERVICE,check=False).returncode or system('is-active','--quiet',SOCKUNIT,check=False).returncode or not manager_exec_matches(exec_start,service_pid):raise RuntimeError('service identity mismatch')
 pre=system('show',SERVICE,'-p','ExecStartPre','--value').stdout
 if pre.count('{ path=')!=1 or '{ path=/usr/bin/python3 ;' not in pre or not re.search(r'\bcode=exited\s*;\s*status=0(?:/SUCCESS)?\s*\}',pre):raise RuntimeError('mask preflight not established')
 guard();result=peer('stop');containment=result.get('containment') or {}
 if result.get('outcome')!='kernel_stopped' or containment!={'closed':True,'frozen':True,'empty':True,'engine_reconciled':False}:raise RuntimeError('stop remains unresolved')
 if CG.stat().st_ino!=c.st_ino or events().get('frozen')!='1' or events().get('populated')!='0':raise RuntimeError('frozen empty observation missing')
 status=peer('status');o=status.get('observation') or {}
 if status.get('outcome')!='status' or not o.get('observed') or o.get('target_id')!=T or o.get('boot_id')!=boot or o.get('cgroup_ino')!=c.st_ino or o.get('engine_reconciled') is not False:raise RuntimeError('status unavailable')
 # No pending Docker start exists in this native fixture; the worker already timed out.
 if any(p.name!=A for p in CG.iterdir() if p.is_dir()):raise RuntimeError('foreign child present')
 system('stop',A);system('stop',S)
 if CG.exists():raise RuntimeError('owned slice still exists')
 system('stop',SOCKUNIT);system('stop',SERVICE)
 if SOCK.exists() or system('is-active','--quiet',SOCKUNIT,check=False).returncode==0 or system('is-active','--quiet',SERVICE,check=False).returncode==0:raise RuntimeError('endpoint cleanup unresolved')
 guard();store(STATE/(T+'.canary-cleanup.json'),{'target_id':T,'slice':S,'inode':c.st_ino,'slice_removed':True,'engine_reconciled':False,'prior_result':'timeout','positive_canary':False})
 print('PASS exact expired native fixture cleanup; no positive sleeper claim; retained permanent closure/catalogue',flush=True)
if __name__=='__main__':main()
