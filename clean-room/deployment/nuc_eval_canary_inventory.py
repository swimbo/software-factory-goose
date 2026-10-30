"""Read-only structural inventory of a failed evaluator reference attempt."""
import json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
G='01M65RMR3F04YB1B016EBBSXGK';BASE=pathlib.Path('/var/lib/software-factory-goose/evaluator')/G;ROOT=old.ETC

def plan():
 if os.geteuid()!=0:raise RuntimeError('root required')
 old.directory(BASE/'broker',0,0,0o700);provision=json.loads(old.read(ROOT/'evaluator-canary-provision-complete.json',0o600));cat=json.loads(old.read(ROOT/'evaluator-canary-catalog.json',0o600,provision['catalog_sha256'],65536))
 if cat.get('generation')!=G or cat.get('purpose')!='synthetic-evaluator-canary-only':raise RuntimeError('fixture unavailable')
 files=sorted(os.listdir(BASE/'broker'))
 if len(files)>256 or any(re.fullmatch(r'[0-9]{2}\.[a-z-]+',name) is None for name in files):raise RuntimeError('inventory unavailable')
 counts={'empty_unfrozen':0,'empty_frozen':0,'populated':0,'other':0}
 for e in cat['challenges']:
  cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+e['target'].lower()+'.slice');st=cg.stat();ev=(cg/'cgroup.events').read_text().splitlines()
  if (st.st_dev,st.st_ino)!=(e['cgroup_dev'],e['cgroup_ino']):raise RuntimeError('cgroup changed')
  if 'populated 1' in ev:counts['populated']+=1
  elif 'populated 0' in ev and 'frozen 0' in ev:counts['empty_unfrozen']+=1
  elif 'populated 0' in ev and 'frozen 1' in ev:counts['empty_frozen']+=1
  else:counts['other']+=1
 result={}
 for unit in ('sfactory-evaluator-canary-coordinator-20261030.service','software-factory-goose-eval-canary.service','software-factory-goose-eval-canary.socket'):
  result[unit]={k:old.ctl('show',unit,'-p',k,'--value') for k in ('LoadState','ActiveState','MainPID','Job','Result')}
 return {'generation':G,'broker_records':files,'cgroup_counts':counts,'units':result,'read_only':True,'provider_called':False}
def apply(approved):
 raise RuntimeError('read-only inventory cannot apply')
