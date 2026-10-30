#!/usr/bin/env python3
"""Read-only inventory of the failed first private recovery. Never repairs or retries."""
import hashlib,json,os,pathlib,stat,subprocess,sys
PREFIX=pathlib.Path('/usr/local/libexec/software-factory-goose')
ETC=pathlib.Path('/etc/software-factory-goose')
STATE=pathlib.Path('/var/lib/software-factory-goose/journal')
RUN=pathlib.Path('/run/software-factory-goose')
UNIT=pathlib.Path('/etc/systemd/system')
NAME='software-factory-goose-private-'
NAMES=['host-net.service','net.service','initdb.service','postgres.service','createdb.service','genesis.service','restate.service','intake.socket','worker.socket','runtime.service','register.service']
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','HOME':'/nonexistent'}

def metadata(path, digest=False):
 try:st=os.lstat(path)
 except FileNotFoundError:return {'exists':False}
 r={'exists':True,'dev':st.st_dev,'ino':st.st_ino,'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode)),'nlink':st.st_nlink,'kind':('file' if stat.S_ISREG(st.st_mode) else 'dir' if stat.S_ISDIR(st.st_mode) else 'socket' if stat.S_ISSOCK(st.st_mode) else 'other')}
 if digest and stat.S_ISREG(st.st_mode):
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   s=os.fstat(fd)
   if (s.st_dev,s.st_ino)!=(st.st_dev,st.st_ino) or s.st_size>300_000_000:raise RuntimeError('inventory identity mismatch')
   h=hashlib.sha256();count=0
   while True:
    b=os.read(fd,65536)
    if not b:break
    count+=len(b)
    if count>s.st_size:raise RuntimeError('inventory file changed')
    h.update(b)
   if count!=s.st_size:raise RuntimeError('inventory file changed')
   r.update(size=count,sha256=h.hexdigest())
  finally:os.close(fd)
 return r

def command(args,limit=8192):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,timeout=15,check=False)
 if len(p.stdout)>limit or len(p.stderr)>limit:raise RuntimeError('inventory output limit')
 return {'status':p.returncode,'stdout':p.stdout.decode('utf8','replace'),'stderr':p.stderr.decode('utf8','replace')}

def main():
 if os.geteuid()!=0 or sys.argv!=[sys.argv[0],'--inventory']:raise RuntimeError('root and exact inventory operation required')
 paths=[ETC/x for x in ('private-bootstrap-started','private-bootstrap-complete','runtime.json','evidence.json','private-genesis.json','private-recovery-started.json','private-recovery-complete.json','private-recovery-runtime.before','private-recovery-host-anchor.before','private-recovery-private-anchor.before','private-resource-limits-started.json','private-resource-limits-complete.json')]
 paths += [RUN/x for x in ('host-netns.json','private-netns.json','host-netns.failed','private-netns.failed','intake.sock','worker.sock')]
 paths += [STATE/x for x in ('pgdata','socket','restate','private-genesis-started','private-genesis-complete')]
 paths += [PREFIX/x for x in ('private-runtime','private-genesis','private-runtime.before','private-genesis.before','private-restate','private-netns-anchor.py','private-register.py')]
 paths += [UNIT/(NAME+x) for x in NAMES]
 files={str(path):metadata(path,digest=path.is_file() and not path.is_symlink()) for path in paths}
 entries=[]
 for name in sorted(os.listdir(STATE)):
  if len(name)>255 or len(entries)>=128:raise RuntimeError('journal inventory limit')
  entries.append({'name':name,'identity':metadata(STATE/name)})
 units={name:command(['/usr/bin/systemctl','show',NAME+name,'--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,MainPID','--no-pager']) for name in NAMES}
 logs=command(['/usr/bin/journalctl','-u',NAME+'genesis.service','-n','30','--no-pager','-o','cat'])
 cluster=None
 if files[str(STATE/'pgdata')]['exists']:
  env={**ENV,'LD_LIBRARY_PATH':str(PREFIX/'postgresql17/lib')}
  p=subprocess.run([str(PREFIX/'postgresql17/bin/pg_controldata'),str(STATE/'pgdata')],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
  if len(p.stdout)>65536 or len(p.stderr)>8192:raise RuntimeError('pg identity output limit')
  lines=[line.split(':',1)[1].strip() for line in p.stdout.decode('utf8','replace').splitlines() if line.startswith('Database system identifier:')]
  cluster={'status':p.returncode,'system_id':lines[0] if len(lines)==1 and lines[0].isdigit() else None}
 print(json.dumps({'paths':files,'journal_entries':entries,'units':units,'genesis_log':logs,'postgres':cluster},sort_keys=True))

if __name__=='__main__':main()
