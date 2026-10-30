#!/usr/bin/env python3
"""Fixed reviewed identity PLAN/APPLY through an owned NUC administrative bridge.

No generic command/code argument. Source is the adjacent installer, pinned by digest.
Exact failed/unknown bridge identity is retained. This is a deployment tool, never a
worker or production ingress. No credentials are accepted or printed.
"""
import hashlib,json,pathlib,subprocess,sys

REMOTE=r'''import hashlib,json,os,pathlib,subprocess,sys,tempfile,uuid
SOURCE=__SOURCE__;OP=__OP__;PLAN=__PLAN__
IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
ROOT=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-identity-admin-'));ROOT.chmod(0o700)
TOKEN=uuid.uuid4().hex;NAME='sfactory-identity-admin-'+TOKEN;LABEL='org.software-factory.identity-admin'
D=['/usr/bin/docker','--host','unix:///run/docker.sock'];ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'}
def cmd(*args,check=True,timeout=20):return subprocess.run(list(args),check=check,capture_output=True,text=True,timeout=timeout,env=ENV)
def save(name,value):
 fd=os.open(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def inspect(target):
 r=cmd(*D,'inspect',target,check=False)
 if r.returncode:
  if 'no such object' in r.stderr.lower():return None
  raise RuntimeError('bridge inspection unavailable')
 objects=json.loads(r.stdout)
 if len(objects)!=1:raise RuntimeError('ambiguous bridge')
 o=objects[0];h=o['HostConfig'];m=o['Mounts']
 caps={x.removeprefix('CAP_') for x in h['CapAdd'] or []}
 if o['Config']['Entrypoint']!=['python3'] or o['Config']['Cmd']!=['-I','-B','-c',boot] or h['Memory']!=192*1024*1024 or h['PidsLimit']!=32 or h['NanoCpus']!=500000000 or h['RestartPolicy']['Name']!='no' or o['Name']!='/'+NAME or (o['Config']['Labels'] or {}).get(LABEL)!=TOKEN or (len(target)==64 and o['Id']!=target) or o['Image']!=IMAGE or o['Config']['User']!='0:0' or h['Privileged'] or h['PidMode']!='host' or h['CgroupnsMode']!='host' or h['NetworkMode']!='none' or not h['ReadonlyRootfs'] or set(h['CapDrop'] or [])!={'ALL'} or caps!={'SYS_CHROOT','DAC_OVERRIDE','CHOWN'} or 'no-new-privileges' not in (h['SecurityOpt'] or []) or len(m)!=1 or m[0]['Source']!='/' or m[0]['Destination']!='/host' or not m[0]['RW']:raise RuntimeError('bridge identity/configuration mismatch')
 return o
def guard():
 info=json.loads(cmd(*D,'inspect','04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062').stdout)[0]
 if info['Name']!='/sf-owner-224a71d2db764249aa6cade3c1b39c80' or info['State']['Status']!='created' or info['State']['Pid']!=0 or (info['Config']['Labels'] or {}).get('org.software-factory.escape-spike')!='224a71d2db764249aa6cade3c1b39c80':raise RuntimeError('original guard changed')
 if cmd(*D,'info','--format','{{.ID}}').stdout.strip()!='56d25a60-5f64-4212-b904-e750067ac6a5' or cmd(*D,'version','--format','{{.Server.GitCommit}}').stdout.strip()!='3ce5872' or cmd('/usr/bin/systemctl','show','docker.service','-p','MainPID','--value').stdout.strip()!='2145':raise RuntimeError('daemon identity changed')
 services={name:cmd('/usr/bin/systemctl','is-active',name).stdout.strip() for name in ('docker.service','hermes-dashboard.service','hermes-gateway.service')}
 if any(v!='active' for v in services.values()):raise RuntimeError('existing service not active')
 return services
save('host-before.json',guard())
save('intent.json',{'name':NAME,'token':TOKEN,'operation':OP,'source_sha256':hashlib.sha256(SOURCE.encode()).hexdigest()})
wrapper="""import fcntl,hashlib,io,json,os,pathlib,sys
source=SOURCE_LITERAL;op=OP_LITERAL;plan=PLAN_LITERAL
if os.geteuid()!=0:raise RuntimeError('root required')
# First prove only CAP_CHOWN's required operation on a newly created inode.
# This file cannot replace or select an existing path; an open fd pins its identity.
if op=='capability-canary':
 root=pathlib.Path(ROOT_LITERAL);name='ownership-canary'
 fd=os.open(root/name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 os.fchown(fd,65534,65534)
 s=os.fstat(fd)
 if (s.st_uid,s.st_gid)!=(65534,65534):raise RuntimeError('ownership transition failed')
 os.fchown(fd,0,0);s=os.fstat(fd)
 if (s.st_uid,s.st_gid)!=(0,0):raise RuntimeError('ownership restoration failed')
 os.close(fd);os.unlink(root/name)
 print('RESULT '+json.dumps({'ownership_capability_verified':True}),flush=True)
else:
 if op not in ('plan','apply'):raise RuntimeError('invalid fixed operation')
 fd=os.memfd_create('sfactory-reviewed-identity',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
 data=source.encode();offset=0
 while offset<len(data):offset+=os.write(fd,data[offset:])
 fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
 namespace={'__name__':'sfactory_identity_install','__file__':'/proc/self/fd/'+str(fd)}
 exec(compile(source,namespace['__file__'],'exec'),namespace)
 host=namespace['Host'](source_digest=hashlib.sha256(data).hexdigest())
 if op=='plan':result=namespace['make_plan'](host)
 else:
  namespace['apply'](host,plan);result={'identities_installed':True,'services_enabled':False}
 print('RESULT '+json.dumps(result,sort_keys=True),flush=True)
""".replace('SOURCE_LITERAL',repr(SOURCE)).replace('OP_LITERAL',repr(OP)).replace('PLAN_LITERAL',repr(PLAN)).replace('ROOT_LITERAL',repr(str(ROOT)))
boot='import os;os.chroot("/host");os.chdir("/");os.execve("/usr/bin/python3",["/usr/bin/python3","-I","-B","-c",'+repr(wrapper)+'],{"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":"/nonexistent","LC_ALL":"C.UTF-8","SYSTEMD_IN_CHROOT":"0"})'
ident=None;complete=False
try:
 if cmd(*D,'info','--format','{{.ID}}').stdout.strip()!='56d25a60-5f64-4212-b904-e750067ac6a5':raise RuntimeError('daemon identity differs')
 r=cmd(*D,'create','--name',NAME,'--label',LABEL+'='+TOKEN,'--network','none','--read-only','--cap-drop','ALL','--cap-add','SYS_CHROOT','--cap-add','DAC_OVERRIDE','--cap-add','CHOWN','--security-opt','no-new-privileges','--pid','host','--cgroupns','host','--pids-limit','32','--memory','192m','--cpus','0.5','--user','0:0','--pull','never','--mount','type=bind,src=/,dst=/host','--entrypoint','python3',IMAGE,'-I','-B','-c',boot)
 ident=r.stdout.strip()
 if len(ident)!=64 or any(c not in '0123456789abcdef' for c in ident):raise RuntimeError('bridge create outcome unavailable')
 o=inspect(ident)
 if o is None or o['State']['Status']!='created' or o['State']['Pid']!=0:raise RuntimeError('bridge prestart state mismatch')
 save('manifest.json',{'id':ident,'name':NAME,'token':TOKEN})
 save('start-intent.json',{'id':ident})
 r=cmd(*D,'start','-a',ident,check=False,timeout=900)
 if len(r.stdout.encode())>65536 or len(r.stderr.encode())>8192:raise RuntimeError('bounded result unavailable')
 if r.returncode!=0:
  save('failure.json',{'returncode':r.returncode,'stderr':r.stderr})
  print(r.stderr,file=sys.stderr,end='');raise RuntimeError('root operation incomplete; retain exact state')
 o=inspect(ident)
 if o is None or o['State']['Running'] or o['State']['Pid']!=0 or o['State']['ExitCode']!=0:raise RuntimeError('bridge completion unresolved')
 lines=[s[7:] for s in r.stdout.splitlines() if s.startswith('RESULT ')]
 if len(lines)!=1:raise RuntimeError('operation result unavailable')
 result=json.loads(lines[0]);save('result.json',result)
 cmd(*D,'rm',ident)
 if inspect(ident) is not None:raise RuntimeError('bridge removal unresolved')
 save('cleanup.json',{'removed':ident});save('host-after.json',guard());complete=True
 print(json.dumps({'root':str(ROOT),'operation':OP,'result':result},sort_keys=True),flush=True)
finally:
 if not complete:print('RETAINED '+str(ROOT)+' bridge='+str(ident or NAME),file=sys.stderr,flush=True)
'''

def main():
 if len(sys.argv) not in (2,3) or sys.argv[1] not in ('capability-canary','plan','apply'):raise SystemExit('usage: nuc_identity_bridge.py capability-canary|plan|apply PLAN_JSON')
 operation=sys.argv[1]
 if (operation=='apply')!=(len(sys.argv)==3):raise SystemExit('apply requires the reviewed plan JSON')
 source=pathlib.Path(__file__).with_name('nuc_identity_install.py').read_text();compile(source,'<identity-installer>','exec')
 plan=json.loads(pathlib.Path(sys.argv[2]).read_text()) if operation=='apply' else None
 if operation=='apply' and (not isinstance(plan,dict) or plan.get('source_sha256')!=hashlib.sha256(source.encode()).hexdigest()):raise SystemExit('plan differs from reviewed source')
 code=REMOTE.replace('__SOURCE__',repr(source)).replace('__OP__',repr(operation)).replace('__PLAN__',repr(plan));compile(code,'<reviewed-remote>','exec')
 subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-I','-B','-'],input=code,text=True,check=True,timeout=950)

if __name__=='__main__':main()
