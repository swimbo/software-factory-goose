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
 (root/'task.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(json.dumps({'root':str(root),'baseline':manifest['baseline'],'spec':SPEC}))

def check(repo):
 manifest={"allowed":["hello.py","test_hello.py"]}
 for name in manifest["allowed"]:
  st=(repo/name).lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>32768:raise RuntimeError("candidate file invalid")
 return check_behavior(repo)

def finalize(root):
 repo=root/'repo';manifest=json.loads((root/'task.json').read_text())
 if git(repo,'rev-parse','HEAD')!=manifest['baseline']:raise RuntimeError('baseline changed')
 if git(repo,'status','--porcelain','--untracked-files=all').splitlines()!=['?? hello.py','?? test_hello.py']:raise RuntimeError('candidate file set differs')
 for name in manifest['allowed']:
  st=(repo/name).lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>32768:raise RuntimeError('candidate file invalid')
 result=json.loads((root/'holdout-result.json').read_text())
 if result.get('groups')!=['pass','pass','pass'] or result.get('candidate_tests')!='pass':raise RuntimeError('holdout failed')
 expected={name:hashlib.sha256((repo/name).read_bytes()).hexdigest() for name in manifest['allowed']}
 if result.get('files')!=expected:raise RuntimeError('evaluated content changed')
 groups=result['groups']
 git(repo,'add','--',*manifest['allowed']);git(repo,'commit','-qm','Implement evaluated greeting CLI')
 revision=git(repo,'rev-parse','HEAD');diff=subprocess.check_output(['git','-C',str(repo),'diff',manifest['baseline'],revision,'--'])
 result={'baseline':manifest['baseline'],'candidate':revision,'diff_sha256':hashlib.sha256(diff).hexdigest(),'holdout_groups':groups,'candidate_tests':'pass','promotion':'pending human action-bound approval','monetary_cap':None}
 (root/'candidate.diff').write_bytes(diff);(root/'evaluation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

def check_behavior(repo):
 def run(*args):
  return subprocess.run(['python3','-I',str(repo/'hello.py'),*args],cwd=repo,capture_output=True,timeout=3,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
 groups=[]
 for cases in [ [([], 'hello world\n'),(['Ada'],'hello Ada\n')], [(['Zoë Smith'],'hello Zoë Smith\n'),(['--uppercase','Ada'],'HELLO ADA\n'),(['Ada','--uppercase'],'HELLO ADA\n')], [(['a','b'],None),(['--bogus'],None)]]:
  for args,expected in cases:
   r=run(*args)
   if expected is None:assert r.returncode==2 and not r.stdout and r.stderr.strip(), 'invalid-input behavior'
   else:assert r.returncode==0 and r.stdout.decode()==expected and not r.stderr, 'greeting behavior'
  groups.append('pass')
 tests=subprocess.run(['python3','-I','-m','unittest','discover','-s',str(repo),'-p','test_hello.py'],cwd=repo,capture_output=True,timeout=10)
 count=re.search(rb'Ran ([0-9]+) tests?',tests.stderr)
 if tests.returncode or not count or int(count[1])<1:raise RuntimeError('candidate tests failed or empty')
 files={name:hashlib.sha256((repo/name).read_bytes()).hexdigest() for name in ('hello.py','test_hello.py')}
 print(json.dumps({'groups':groups,'candidate_tests':'pass','files':files}))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['create','check','finalize']);p.add_argument('root',type=pathlib.Path);a=p.parse_args();{'create':create,'check':check,'finalize':finalize}[a.action](a.root)
