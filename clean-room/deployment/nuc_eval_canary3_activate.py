"""Activate only the synthetic evaluator broker; does not run a challenge."""
import hashlib,json,os,pathlib,stat
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGP';NAME='software-factory-goose-eval-canary3';DEST=old.PREFIX/'evaluator3';PARENT=old.RUN/'evaluator3';SOCKET=PARENT/'broker.sock';ROOT=old.ETC
START=ROOT/'evaluator-canary3-activation-started.json';DONE=ROOT/'evaluator-canary3-activation-complete.json';ATTEST=DEST/'broker-attestation.json'
def require(x,msg):
 if not x:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,ATTEST,SOCKET)),'activation state occupied');old.directory(DEST,0,2002,0o710);old.directory(PARENT,0,2002,0o710)
 install=json.loads(old.read(ROOT/'evaluator-canary3-service-complete.json',0o600));require(install=={'generation':G,'installed':True,'started':False,'fixture_only':True},'fixture unavailable')
 pins=json.loads(old.read(ROOT/'evaluator-canary3-service-started.json',0o600));unit=old.UNIT/(NAME+'.service');socket_unit=old.UNIT/(NAME+'.socket');old.read(unit,0o644,pins['service_sha256']);old.read(socket_unit,0o644,pins['socket_sha256'])
 for n in (NAME+'.service',NAME+'.socket'):
  for k,v in (('LoadState','loaded'),('ActiveState','inactive'),('Names',n),('FragmentPath',str(old.UNIT/n)),('DropInPaths',''),('Job','')):require(old.ctl('show',n,'-p',k,'--value')==v,'unit unavailable')
 complete=json.loads(old.read(ROOT/'evaluator-canary3-provision-complete.json',0o600));raw=old.read(ROOT/'evaluator-canary3-catalog.json',0o600,complete['catalog_sha256'],65536);cat=json.loads(raw);require(cat['generation']==G and cat['purpose']=='synthetic-evaluator-canary3-only' and len(cat['challenges'])==22 and not os.listdir('/var/lib/software-factory-goose/evaluator/'+G+'/broker'),'fixture unavailable')
 for item in cat['challenges']:
  cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+item['target'].lower()+'.slice');st=os.stat(cg);events=(cg/'cgroup.events').read_text().splitlines();require((st.st_dev,st.st_ino)==(item['cgroup_dev'],item['cgroup_ino']) and events.count('frozen 0')==1 and events.count('populated 0')==1,'target unavailable')
 # The fixed runtime checks all ten source pins from the fixture provision intent.
 runtime=DEST/'nuc_registry_eval_canary_runtime.py';up={'runtime_sha256':json.loads(old.read(ROOT/'evaluator-canary3-provision-started.json',0o600))['source_sha256']['nuc_registry_eval_canary_runtime.py']};fd=os.open(runtime,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);old.noacl(fd);require((st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2002,1,0o440) and st.st_size<=1000000,'runtime unavailable');source=os.read(fd,1000001);require(hashlib.sha256(source).hexdigest()==up['runtime_sha256'],'runtime changed')
 finally:os.close(fd)
 # Read-only compile cannot execute main; imports are the fixed installed files.
 import sys
 sys.path.insert(0,str(DEST));sys.path.insert(0,str(old.PREFIX/'relay'));ns={'__name__':'synthetic_runtime_validation'};exec(compile(source,'<verified-canary-runtime>','exec'),ns);ns['verify_sources']()
 return {'generation':G,'catalog_sha256':complete['catalog_sha256'],'service_sha256':pins['service_sha256'],'socket_sha256':pins['socket_sha256'],'runtime_sha256':up['runtime_sha256'],'scope':'start synthetic idle broker only; no evaluation request'}
def apply(approved):
 require(plan()==approved,'activation plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 old.ctl('start',NAME+'.socket');old.ctl('start',NAME+'.service')
 pid=int(old.ctl('show',NAME+'.service','-p','MainPID','--value'));require(pid>1 and old.ctl('show',NAME+'.service','-p','ActiveState','--value')=='active' and old.ctl('show',NAME+'.service','-p','Job','--value')=='' and old.ctl('show',NAME+'.socket','-p','Job','--value')=='','broker unavailable')
 fields=dict(line.split(':',1) for line in pathlib.Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line);require(fields.get('Uid','').split()==['0']*4 and fields.get('Gid','').split()==['0']*4 and fields.get('NoNewPrivs','').strip()=='1' and all(int(fields[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')),'broker privileges unavailable')
 s=os.lstat(SOCKET);require(stat.S_ISSOCK(s.st_mode) and (s.st_uid,s.st_gid,s.st_nlink,stat.S_IMODE(s.st_mode))==(0,2002,1,0o660),'socket unavailable')
 try:os.getxattr(SOCKET,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==old.errno.ENODATA,'socket ACL unavailable')
 else:raise RuntimeError('socket ACL forbidden')
 result={'generation':G,'pid':pid,'socket_dev':s.st_dev,'socket_ino':s.st_ino,'fixture_only':True,'challenge_started':False};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
