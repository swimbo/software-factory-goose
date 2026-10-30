#!/usr/bin/env python3
"""Disposable no-network Linux UID2000 registry loader proof; no host authority."""
import hashlib,json,os,pathlib,shutil,subprocess,tempfile,uuid
D=['/usr/bin/docker','--host','unix:///run/docker.sock'];IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937';LABEL='org.software-factory.registry-loader-fixture'
SOURCE=pathlib.Path('/tmp/sfactory-runtime-build.PjU7pCOX/target/debug/examples/catalog_registry_probe');ETC=pathlib.Path('/etc/software-factory-goose')
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C'}
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def cmd(args,timeout=30):
 p=subprocess.run(list(map(str,args)),env=ENV,capture_output=True,timeout=timeout,check=False);require(len(p.stdout)<=65536 and len(p.stderr)<=65536,'output bound');return p
def save(root,name,value):
 path=root/name;fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:os.write(fd,json.dumps(value,sort_keys=True).encode());os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def packed(v):return json.dumps(v,ensure_ascii=False,separators=(',',':')).encode()
CODE=r'''import json,os,pathlib,shutil,sys
mode=sys.argv[1];root=pathlib.Path('/etc/software-factory-goose');root.mkdir(mode=0o711);os.chmod(root,0o711)
for p in pathlib.Path('/fixture').glob('*.json'):
 dest=root/p.name;shutil.copyfile(p,dest);os.chmod(dest,0o644)
if mode=='changed':
 with open(root/'real-runtime.json','ab') as f:f.write(b' ')
if mode=='missing':os.unlink(root/'grant-runtime.json')
if mode in ('access-acl','default-acl'):
 import struct
 acl=struct.pack('<I',2)+b''.join(struct.pack('<HHI',tag,perm,ident) for tag,perm,ident in [(1,7,0xffffffff),(2,4,2001),(4,1,0xffffffff),(16,1,0xffffffff),(32,1,0xffffffff)])
 os.setxattr(root,'system.posix_acl_access' if mode=='access-acl' else 'system.posix_acl_default',acl)
os.setgroups([]);os.setgid(2000);os.setuid(2000)
os.execve('/probe',['/probe'],{'PATH':'/usr/bin:/bin','HOME':'/nonexistent'})
'''
def main():
 require(os.getuid()==1000 and os.geteuid()==1000,'fixture uid mismatch');root=pathlib.Path(tempfile.mkdtemp(prefix='sfactory-registry-loader-',dir='/tmp'));root.chmod(0o700)
 save(root,'intent.json',{'scope':'disposable registry loader only'})
 payload=root/'payload';payload.mkdir(mode=0o755);payload.chmod(0o755)
 names=['runtime.json','evidence.json','grant-runtime.json','grant-evidence.json','real-runtime.json','real-evidence.json']
 for name in names:shutil.copyfile(ETC/name,payload/name);os.chmod(payload/name,0o644)
 real=json.loads((payload/'real-runtime.json').read_bytes());new=dict(real);new.update(intent_id='01ARZ3NDEKTSV4RRFFQ69G5FAN',task_id='01ARZ3NDEKTSV4RRFFQ69G5FAM',queue_id='registry-fixture-queue',worker_id='registry-fixture-worker',sdk_port=9084)
 request=new['request'];facts=new['facts'];req={k:request[k] for k in ('schema_version','repository','target_ref','base_revision','intent','acceptance_criteria')};fac={k:facts[k] for k in ('spec_clarity','blast_radius','novelty','reversibility','has_codified_knowledge','fatal')}
 fingerprint=hashlib.sha256(packed([new['principal'],new['queue_id'],new['intent_id'],new['task_id'],req,fac,new['evidence_sha256']])).hexdigest();scope=dict(new['launch_scope']);scope.update(intent_id=new['intent_id'],task_id=new['task_id'],queue_id=new['queue_id'],worker_id=new['worker_id'],generation='01ARZ3NDEKTSV4RRFFQ69G5FAK',catalog_sha256=fingerprint);new['launch_scope']=scope
 (payload/'new-runtime.json').write_bytes(packed(new));os.chmod(payload/'new-runtime.json',0o644);shutil.copyfile(payload/'real-evidence.json',payload/'new-evidence.json');os.chmod(payload/'new-evidence.json',0o644)
 fps=['e6e11a0b060dc2760f4c44ba607c45a931c01b839039158cbbec1e5f7e9ebbaf','4218228a2a9c0fcc51ec838414ebd92542b18e06ddd40d7a1a2b628d4d8caf19','cc5c4ae8ec34730f037fddefcb7b6d92fd4eab2bc1ac06dabd92abd747c1f1b7',fingerprint]
 entries=[]
 for config,evidence,fp in zip(('runtime.json','grant-runtime.json','real-runtime.json','new-runtime.json'),('evidence.json','grant-evidence.json','real-evidence.json','new-evidence.json'),fps):entries.append({'config':config,'evidence':evidence,'config_sha256':hashlib.sha256((payload/config).read_bytes()).hexdigest(),'evidence_sha256':hashlib.sha256((payload/evidence).read_bytes()).hexdigest(),'catalog_sha256':fp})
 (payload/'catalog-registry.json').write_bytes(packed({'schema':1,'active_intent':new['intent_id'],'entries':entries}));os.chmod(payload/'catalog-registry.json',0o644)
 shutil.copyfile(SOURCE,root/'probe');p=cmd(['/usr/bin/strip',root/'probe']);require(p.returncode==0,'strip failed');os.chmod(root/'probe',0o755)
 for mode in ('valid','changed','missing','access-acl','default-acl'):
  token=uuid.uuid4().hex;name='sfactory-registry-loader-'+token;save(root,mode+'-intent.json',{'name':name,'token':token})
  args=D+['create','--pull=never','--name',name,'--label',LABEL+'='+token,'--network=none','--read-only','--cap-drop=ALL','--cap-add=SETUID','--cap-add=SETGID','--security-opt=no-new-privileges','--pids-limit=16','--memory=128m','--cpus=0.5','--restart=no','--user=0:0','--tmpfs=/etc:rw,size=4m,mode=0755','--mount',f'type=bind,src={payload},dst=/fixture,readonly','--mount',f'type=bind,src={root}/probe,dst=/probe,readonly','--entrypoint','/usr/local/bin/python3',IMAGE,'-I','-B','-c',CODE,mode]
  p=cmd(args);require(p.returncode==0,'create unknown');cid=p.stdout.decode().strip();require(len(cid)==64,'invalid container ID');save(root,mode+'-id.json',{'id':cid})
  p=cmd(D+['inspect',cid]);require(p.returncode==0,'inspect unavailable');obj=json.loads(p.stdout)[0];require(obj['Id']==cid and obj['Name']=='/'+name and obj['State']['Status']=='created' and (obj['Config'].get('Labels') or {}).get(LABEL)==token and obj['Image']==IMAGE and obj['HostConfig']['NetworkMode']=='none','created container mismatch')
  p=cmd(D+['start','--attach',cid],45);passed=p.returncode==0
  if mode=='valid':require(passed and json.loads(p.stdout)=={'catalogs':4,'intent':new['intent_id'],'task':new['task_id'],'generation':scope['generation'],'catalog_sha256':fingerprint},'valid registry refused')
  else:
   require(not passed,'invalid registry accepted')
   expected={'changed':b'preserved catalog bytes changed','missing':b'No such file or directory','access-acl':b'registry ancestor ACL unavailable','default-acl':b'registry ancestor ACL unavailable'}[mode]
   require(expected in p.stderr,'negative control failed before loader rejection')
  p=cmd(D+['inspect',cid]);require(p.returncode==0 and json.loads(p.stdout)[0]['State']['Status']=='exited','terminal state unavailable')
  p=cmd(D+['rm',cid]);require(p.returncode==0 and p.stdout.decode().strip()==cid,'cleanup unknown');save(root,mode+'-complete.json',{'id':cid,'removed':True,'expected':True})
 save(root,'complete.json',{'positive_and_negative_passed':True});print('PASS: UID2000 loader accepts four root catalogs and rejects changed/missing history and access/default ACLs; no network')
 shutil.rmtree(root)
if __name__=='__main__':main()
