#!/usr/bin/env python3
"""Read-only reconciliation of one timed-out fixture create; never starts/removes it."""
import hashlib,json,os,pathlib,subprocess,time
TOKEN='224a71d2db764249aa6cade3c1b39c80'
NAME='sf-owner-'+TOKEN
IDENT='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062'
IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
SLICE='sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0-worker.slice'
ROOT=pathlib.Path('/tmp/sfactory-writer-preflight.WdzouOy1')
def command(*args):return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10).stdout.decode().strip()
def main():
 root=ROOT/'reconciliation';root.mkdir(mode=0o700)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if st.st_uid!=os.getuid() or st.st_mode&0o777!=0o700:raise RuntimeError('unsafe record root')
  daemon_id=command('/usr/bin/docker','info','--format','{{.ID}}');version=command('/usr/bin/docker','version','--format','{{.Server.Version}} {{.Server.GitCommit}}')
  pid=command('/usr/bin/systemctl','show','docker.service','--property=MainPID','--value')
  if daemon_id!='56d25a60-5f64-4212-b904-e750067ac6a5' or version!='29.8.0 3ce5872' or not pid.isdigit() or int(pid)<=1:raise RuntimeError('daemon identity changed')
  obj=json.loads(command('/usr/bin/docker','inspect',IDENT))[0];h=obj['HostConfig'];c=obj['Config'];state=obj['State']
  mounts={(v['Source'],v['Destination'],v['RW']) for v in obj['Mounts']}
  expected={('/tmp/sfactory-gate-linux.X4ZjF1LB/goose-build/goose-linux-fixture','/goose',False),(str(ROOT/'batch-yrewptj8/fixtures'),'/fixtures',False),(str(ROOT/'batch-yrewptj8/gate'),'/gate',False)}
  if not (obj['Id']==IDENT and obj['Name']=='/'+NAME and obj['Image']==IMAGE and state['Status']=='created' and not state['Running'] and state['Pid']==0 and state['StartedAt']=='0001-01-01T00:00:00Z' and obj['RestartCount']==0 and c['User']=='1001:1001' and c['Entrypoint']==['python3'] and c['Cmd']==['-B','/fixtures/nuc_goose_relay_worker.py'] and c['Labels']=={'org.software-factory.escape-spike':TOKEN} and 'SFACTORY_TOOL_MODE=write_files' in c['Env'] and 'SFACTORY_TASK_PROMPT=Synthetic fixture only: call factory write_files once with both requested files, then finish.' in c['Env'] and h['CgroupParent']==SLICE and h['NetworkMode']=='none' and h['ReadonlyRootfs'] and h['CapDrop']==['ALL'] and h['SecurityOpt']==['no-new-privileges'] and h['RestartPolicy']['Name']=='no' and not h['Privileged'] and h['PidsLimit']==24 and h['Memory']==134217728 and h['NanoCpus']==500000000 and h['Tmpfs']=={'/work':'rw,exec,nosuid,nodev,size=128m,mode=1777'} and mounts==expected):raise RuntimeError('original specification mismatch')
  processes=command('/bin/ps','-eo','pid,args')
  if any(('nuc_goose_relay_batch.py' in line or ('docker create' in line and TOKEN in line)) for line in processes.splitlines()):raise RuntimeError('old controller may be alive')
  events=pathlib.Path('/sys/fs/cgroup/sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice/'+SLICE+'/cgroup.events').read_text()
  if 'populated 0\n' not in events:raise RuntimeError('slice not empty')
  record={'kind':'observed-original-created','token':TOKEN,'name':NAME,'container_id':IDENT,'daemon_id':daemon_id,'daemon_pid':int(pid),'engine':version,'observed_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'log_sha256':hashlib.sha256((ROOT/'run2.log').read_bytes()).hexdigest(),'cgroup_events':events,'conditions':'valid only while same daemon and exact original remains created under this name; do not start, rename or remove'}
  out=os.open('original.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600,dir_fd=fd)
  with os.fdopen(out,'w') as f:json.dump(record,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
  os.fsync(fd);print(json.dumps(record,sort_keys=True))
 finally:os.close(fd)
if __name__=='__main__':main()
