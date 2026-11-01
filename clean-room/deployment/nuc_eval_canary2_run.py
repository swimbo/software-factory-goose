"""One-shot synthetic evaluator coordinator; no real task or provider."""
import hashlib,json,os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGN';NAME='sfactory-evaluator-canary2-coordinator-20261030.service';ROOT=old.ETC;BASE=pathlib.Path('/var/lib/software-factory-goose/evaluator')/G
START=ROOT/'evaluator-canary2-run-started.json';DONE=ROOT/'evaluator-canary2-run-complete.json';SCRIPTDIR=old.PREFIX/'evaluator2'
CODE="""import os,pathlib,runpy
if os.getuid()!=2002 or os.geteuid()!=2002 or os.getgid()!=2002 or os.getegid()!=2002:raise RuntimeError('identity unavailable')
f=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
if f.get('NoNewPrivs','').strip()!='1' or any(int(f[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')):raise RuntimeError('privileges unavailable')
runpy.run_path('/usr/local/libexec/software-factory-goose/evaluator2/nuc_registry_eval_canary_coordinator.py',run_name='__main__')
"""
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE)) and old.ctl('show',NAME,'-p','LoadState','--value')=='not-found','run already attempted')
 att=json.loads(old.read(ROOT/'evaluator-canary2-attestation-complete.json',0o600));activation=json.loads(old.read(ROOT/'evaluator-canary2-activation-complete.json',0o600));provision=json.loads(old.read(ROOT/'evaluator-canary2-provision-complete.json',0o600));raw=old.read(ROOT/'evaluator-canary2-catalog.json',0o600,provision['catalog_sha256'],65536);cat=json.loads(raw)
 require(att.get('generation')==G and att.get('fixture_only') is True and activation.get('generation')==G and activation.get('pid')==att.get('pid') and cat.get('generation')==G and cat.get('purpose')=='synthetic-evaluator-canary2-only' and len(cat.get('challenges',[]))==22 and not os.listdir(BASE/'broker'),'fixture unavailable')
 old.directory(SCRIPTDIR,0,2002,0o710)
 for name,expected in [('broker-attestation.json',att['manifest_sha256']),('scope.json',None)]:
  fd=os.open(SCRIPTDIR/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   st=os.fstat(fd);old.noacl(fd);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(0,2002,1,0o440) and st.st_size<=8192,'scope or attestation unavailable');data=os.read(fd,8193);require(len(data)==st.st_size and (expected is None or hashlib.sha256(data).hexdigest()==expected),'scope or attestation changed')
   if name=='scope.json':require(json.loads(data)=={'schema':1,'generation':G,'candidate_sha256':cat['snapshot_sha256']},'scope mismatch')
  finally:os.close(fd)
 for parent in ('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system'):
  for path in (pathlib.Path(parent)/NAME,pathlib.Path(parent)/(NAME+'.d'),pathlib.Path(parent)/'service.d'):require(not os.path.lexists(path),'unit alias or drop-in occupied')
 require(old.ctl('show','software-factory-goose-eval-canary2.service','-p','MainPID','--value')==str(att['pid']) and old.ctl('show','software-factory-goose-eval-canary2.service','-p','ActiveState','--value')=='active','broker unavailable')
 for item in cat['challenges']:
  cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+item['target'].lower()+'.slice');st=cg.stat();e=(cg/'cgroup.events').read_text().splitlines();require((st.st_dev,st.st_ino)==(item['cgroup_dev'],item['cgroup_ino']) and e.count('populated 0')==1 and e.count('frozen 0')==1,'challenge unavailable')
 return {'generation':G,'catalog_sha256':provision['catalog_sha256'],'attestation_sha256':att['manifest_sha256'],'code_sha256':hashlib.sha256(CODE.encode()).hexdigest(),'candidate_sha256':cat['snapshot_sha256'],'unit':NAME,'scope':'synthetic reference candidate only; no model or provider'}
def apply(approved):
 require(plan()==approved,'run plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 args=['/usr/bin/systemd-run','--unit='+NAME,'--wait','--pipe','--quiet','--property=User=sfgoose-eval','--property=Group=sfgoose-eval','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=PrivateNetwork=yes','--property=RestrictAddressFamilies=AF_UNIX','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=MemoryMax=128M','--property=TasksMax=16','--property=RuntimeMaxSec=700s','--property=LimitCORE=0','/usr/bin/python3','-I','-B','-c',CODE]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=750,check=False)
 require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'coordinator outcome unknown')
 result=json.loads(p.stdout);require(set(result)=={'schema','generation','candidate_sha256','scenario_votes','repetitions','candidate_tests','challenges'} and result['schema']==1 and result['generation']==G and result['candidate_sha256']==approved['candidate_sha256'] and result['scenario_votes']==[3]*7 and result['repetitions']==3 and result['candidate_tests']=='pass' and result['challenges']==22,'synthetic result unavailable')
 require(old.ctl('show',NAME,'-p','MainPID','--value')=='0' and old.ctl('show',NAME,'-p','Job','--value')=='' and old.ctl('show',NAME,'-p','Result','--value')=='success','coordinator termination unavailable')
 out={'generation':G,'fixture_only':True,'candidate_sha256':result['candidate_sha256'],'scenario_votes':result['scenario_votes'],'candidate_tests':'pass','challenges':22,'provider_called':False};old.store(DONE,json.dumps(out,sort_keys=True).encode()+b'\n',0o600);return out
