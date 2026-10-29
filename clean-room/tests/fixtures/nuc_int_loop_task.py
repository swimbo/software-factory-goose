#!/usr/bin/env python3
"""Create a disposable task repo and independently evaluate its candidate."""
import argparse, hashlib, json, pathlib, re, stat, subprocess

SPEC = '''Build a dependency-free Python 3 CLI in hello.py. Running python3 hello.py prints hello world followed by one newline. One positional name replaces world, preserving spaces and Unicode. Optional --uppercase may occur before or after the name and uppercases the whole greeting. More than one name or any unknown option must exit 2, print no stdout, and explain usage on stderr. Add unittest tests in test_hello.py. Only these two files may be added; do not modify the baseline README. No network, third-party dependencies, or external files are needed.'''

def git(root,*args):
 return subprocess.check_output(['git','-C',str(root),*args],stderr=subprocess.DEVNULL).decode().strip()

def create(root):
 root.mkdir(mode=0o700)
 repo=root/'repo';repo.mkdir(mode=0o755)
 (repo/'README.md').write_text('Disposable software-factory Goose INT-LOOP task.\n')
 git(repo,'init','-q');git(repo,'config','user.name','Factory INT-LOOP');git(repo,'config','user.email','factory-int-loop@localhost');git(repo,'add','README.md');git(repo,'commit','-qm','Initialize owned INT-LOOP task')
 manifest={'spec':SPEC,'baseline':git(repo,'rev-parse','HEAD'),'allowed':['hello.py','test_hello.py'],'monetary_cap':None}
 (root/'task.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'task.json').chmod(0o600)
 print(json.dumps({'root':str(root),'baseline':manifest['baseline'],'spec':SPEC}))

def finalize(root):
 repo=root/'repo';manifest=json.loads((root/'task.json').read_text())
 if git(repo,'rev-parse','HEAD')!=manifest['baseline']:raise RuntimeError('baseline changed')
 if git(repo,'status','--porcelain','--untracked-files=all').splitlines()!=['?? hello.py','?? test_hello.py']:raise RuntimeError('candidate file set differs')
 for name in manifest['allowed']:
  st=(repo/name).lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>32768:raise RuntimeError('candidate file invalid')
 result=json.loads((root/'holdout-result.json').read_text())
 if result.get('groups')!=['pass','pass','pass'] or result.get('candidate_tests')!='pass':raise RuntimeError('holdout failed')
 if result.get('repetitions')!=3 or not isinstance(result.get('scenario_votes'),list) or len(result['scenario_votes'])!=7 or any(type(v) is not int or v not in (2,3) for v in result['scenario_votes']):raise RuntimeError('holdout repetition evidence missing')
 if sum(result['scenario_votes'])*10<7*3*9:raise RuntimeError('holdout aggregate below 90 percent')
 expected={name:hashlib.sha256((repo/name).read_bytes()).hexdigest() for name in manifest['allowed']}
 if result.get('files')!=expected:raise RuntimeError('evaluated content changed')
 groups=result['groups']
 git(repo,'add','--',*manifest['allowed']);git(repo,'commit','-qm','Implement evaluated greeting CLI')
 revision=git(repo,'rev-parse','HEAD')
 for name,digest in expected.items():
  blob=subprocess.check_output(['git','-C',str(repo),'show',revision+':'+name])
  if hashlib.sha256(blob).hexdigest()!=digest:raise RuntimeError('committed content differs from evaluation')
 diff=subprocess.check_output(['git','-C',str(repo),'diff',manifest['baseline'],revision,'--'])
 result={'baseline':manifest['baseline'],'candidate':revision,'diff_sha256':hashlib.sha256(diff).hexdigest(),'holdout_groups':groups,'scenario_votes':result['scenario_votes'],'repetitions':3,'candidate_tests':'pass','promotion':'pending human action-bound approval','monetary_cap':None}
 (root/'candidate.diff').write_bytes(diff);(root/'evaluation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

def check_behavior(run, run_tests, files):
 """Host-held challenges; callbacks MUST execute only in the owned sandbox.

 No candidate subprocess is ever launched here. No holdout code is mounted
 into a candidate container. The caller supplies immutable snapshot hashes.
 """
 groups=[];votes=[]
 for cases in [ [([], 'hello world\n'),(['Ada'],'hello Ada\n')], [(['Zoë Smith'],'hello Zoë Smith\n'),(['--uppercase','Ada'],'HELLO ADA\n'),(['Ada','--uppercase'],'HELLO ADA\n')], [(['a','b'],None),(['--bogus'],None)]]:
  for args,expected in cases:
   passed=0
   for repetition in range(3):
    r=run(*args)
    if expected is None:
     passed+=int(r.returncode==2 and not r.stdout and bool(r.stderr.strip()))
    else:passed+=int(r.returncode==0 and r.stdout==expected.encode() and not r.stderr)
   votes.append(passed)
   if passed<2:raise RuntimeError('invalid-input behavior' if expected is None else 'greeting behavior')
  groups.append('pass')
 if sum(votes)*10<len(votes)*3*9:raise RuntimeError('holdout aggregate below 90 percent')
 tests=run_tests()
 count=re.search(rb'Ran ([0-9]+) tests?',tests.stderr)
 if tests.returncode or not count or int(count[1])<1:raise RuntimeError('candidate tests failed or empty')
 return {'groups':groups,'scenario_votes':votes,'repetitions':3,'candidate_tests':'pass','files':files}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['create','finalize']);p.add_argument('root',type=pathlib.Path);a=p.parse_args();{'create':create,'finalize':finalize}[a.action](a.root)
