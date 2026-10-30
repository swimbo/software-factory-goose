#!/usr/bin/env python3
"""Resolve only the recorded failed-start canary; never target the old guard."""
import pathlib,runpy,subprocess,sys
m=runpy.run_path(str(pathlib.Path(__file__).with_name('nuc_barrier_canary.py')))
ROOT=r'''import json,os,pathlib,subprocess
R=pathlib.Path('/tmp/sfactory-barrier-leqm9isi'); S='sfactorya8b2e0eadc6d47e8aa46a6999436f0b1.slice'; A='sfactorya8b2e0eadc6d47e8aa46a6999436f0b1-anchor.service'; CG=pathlib.Path('/sys/fs/cgroup')/S; INODE=7546233
L='8cb7d67b7696ccbbdf68f7a724d7eae15a48ce4f0a110cde3d0b6b303793af6a'; GT='224a71d2db764249aa6cade3c1b39c80'; GUARD='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062'
D=['/usr/bin/docker','--host','unix:///run/docker.sock']; E={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'}
def run(*a,check=True):
 env=dict(E)
 if a[0]=='/usr/bin/systemctl':env['SYSTEMD_IN_CHROOT']='0'
 p=subprocess.run(list(a),capture_output=True,text=True,timeout=20,env=env)
 if check and p.returncode:print('FIXED_COMMAND_FAILURE '+json.dumps({'code':p.returncode,'stderr':p.stderr[:1024]}),flush=True);raise RuntimeError('fixed operation failed')
 return p
def docker(*a,check=True):return run(*D,*a,check=check)
def state():return dict(x.split() for x in (CG/'cgroup.events').read_text().splitlines())
def record(name):
 p=R/name;fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);st=os.fstat(fd)
 if st.st_uid!=0 or st.st_mode & 0o777!=0o600:raise RuntimeError('untrusted record')
 with os.fdopen(fd) as f:return json.load(f)
def save(name,value):
 fd=os.open(R/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(R,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def guard():
 info=json.loads(docker('info','--format','{{json .}}').stdout);pid=run('/usr/bin/systemctl','show','docker.service','-p','MainPID','--value').stdout.strip();commit=docker('version','--format','{{.Server.GitCommit}}').stdout.strip();o=json.loads(docker('inspect',GUARD).stdout)[0]
 if info.get('ID')!='56d25a60-5f64-4212-b904-e750067ac6a5' or pid!='2145' or commit!='3ce5872' or o['Id']!=GUARD or o['Name']!='/sf-owner-'+GT or (o['Config']['Labels'] or {}).get('org.software-factory.escape-spike')!=GT or o['State']['Status']!='created' or o['State']['Pid']!=0:raise RuntimeError('guard changed')
late=record('late-manifest.json'); closed=record('closed.json'); sl=record('slice.json'); pos=record('positive-manifest.json')
if late.get('id')!=L or late.get('role')!='late' or late.get('slice')!=S or late.get('slice_inode')!=INODE or pos.get('role')!='positive' or pos.get('slice')!=S or pos.get('slice_inode')!=INODE or closed!={'slice':S,'inode':INODE,'late_id':L} or sl!={'slice':S,'inode':INODE,'anchor':A}:raise RuntimeError('record mismatch')
if CG.is_symlink() or CG.resolve(strict=True)!=CG or CG.stat().st_ino!=INODE or state().get('frozen')!='1' or state().get('populated')!='0':raise RuntimeError('frozen empty subtree unverified')
guard();o=json.loads(docker('inspect',L).stdout)[0]
if o['Id']!=L or o['Name']!='/'+late['name'] or (o['Config']['Labels'] or {}).get('org.software-factory.barrier-worker')!=late['token'] or o['HostConfig']['CgroupParent']!=S or o['State']['Status']!='created' or o['State']['Pid']!=0 or o['State']['Running']:raise RuntimeError('late target mismatch')
old=docker('inspect',pos['id'],check=False)
if old.returncode==0 or 'no such object' not in old.stderr.lower():raise RuntimeError('positive object unresolved')
desc=run('/usr/bin/systemctl','show',A,'-p','Description','--value').stdout.strip();group=run('/usr/bin/systemctl','show',A,'-p','ControlGroup','--value').stdout.strip()
if desc!=A or group not in ('','/'+S+'/'+A):raise RuntimeError('anchor mismatch')
allowed={A,'docker-'+L+'.scope','docker-'+pos['id']+'.scope'}
if any(p.name not in allowed for p in CG.iterdir() if p.is_dir()):raise RuntimeError('foreign child in slice')
# Moby 3ce5872 serializes same-ID start/remove using the state lock.
docker('rm',L)
after=docker('inspect',L,check=False)
if after.returncode==0 or 'no such object' not in after.stderr.lower():raise RuntimeError('late target removal unresolved')
if CG.stat().st_ino!=INODE or state().get('frozen')!='1' or state().get('populated')!='0':raise RuntimeError('frozen empty proof changed')
guard();save('reconcile-late.json',{'id':L,'daemon_id':'56d25a60-5f64-4212-b904-e750067ac6a5','daemon_pid':2145,'slice':S,'inode':INODE,'removed_nonforce':True,'frozen':True,'populated':0})
# No further start is admitted by the retained closed record and exact-ID removal.
if any(p.name not in allowed for p in CG.iterdir() if p.is_dir()):raise RuntimeError('foreign child in slice')
run('/usr/bin/systemctl','stop',A);run('/usr/bin/systemctl','stop',S)
if CG.exists():raise RuntimeError('slice retained by system manager')
guard();save('reconcile-slice.json',{'slice':S,'inode':INODE,'anchor':A,'removed':True})
print('RESULT '+json.dumps({'state':'reconcile_passed','late_id_removed':True,'slice_removed':True}),flush=True)
'''
source=m['REMOTE'].replace('canary_passed','reconcile_passed').replace('canary_failed','reconcile_failed').replace('__ROOT_SCRIPT__',repr(ROOT))
compile(ROOT,'<root>','exec');compile(source,'<remote>','exec')
if __name__=='__main__':
 r=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=source,text=True,timeout=120)
 sys.exit(r.returncode)
