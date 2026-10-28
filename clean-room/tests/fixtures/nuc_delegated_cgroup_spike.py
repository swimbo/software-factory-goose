#!/usr/bin/env python3
"""Run on the authorized NUC: disposable delegated systemd subtree only."""
import pathlib
import subprocess
import tempfile
import uuid

MANAGER = r'''import os,subprocess,sys,time
from pathlib import Path
root=Path(sys.argv[1]); path=Path('/sys/fs/cgroup') / open('/proc/self/cgroup').read().strip().split('::',1)[1].lstrip('/')
assert path.name == sys.argv[2]
worker=path/'worker'; sibling=path/'sibling'; worker.mkdir(); sibling.mkdir()
processes=[]
def populated(group):
    return dict(line.split() for line in (group/'cgroup.events').read_text().splitlines())['populated']
def spawn(code, group, *args):
    def enter():
        with open(group/'cgroup.procs','w') as f: f.write(str(os.getpid()))
    p=subprocess.Popen([sys.executable,'-c',code,*map(str,args)],preexec_fn=enter)
    processes.append(p)
    return p
def waitfile(name, seconds=5):
    limit=time.monotonic()+seconds
    while time.monotonic()<limit:
        if (root/name).exists(): return
        time.sleep(.01)
    raise RuntimeError('missing '+name)
def kill_cgroup(group):
    with open(group/'cgroup.kill','w') as f: f.write('1')
def reap(p):
    if p.poll() is None: p.kill()
    p.wait(timeout=4)
TREE = """import os,sys,time
root=sys.argv[1]; p=os.fork()
if p==0:
 os.setsid(); assert os.getsid(0)==os.getpid()
 open(root+'/ready.tmp','w').write(open('/proc/self/cgroup').read()); os.replace(root+'/ready.tmp',root+'/ready')
 time.sleep(2); open(root+'/marker','w').write('alive'); time.sleep(4); os._exit(0)
time.sleep(7)
"""
MIGRATE = """import os,sys,time
open(sys.argv[1]+'/cgroup.procs','w').write(str(os.getpid()))
open(sys.argv[2]+'/moved','w').write(open('/proc/self/cgroup').read())
time.sleep(6)
"""
try:
    # No-kill positive control, followed by owned cleanup.
    p=spawn(TREE,worker,root); waitfile('ready'); waitfile('marker',4)
    kill_cgroup(worker); reap(p)
    limit=time.monotonic()+4
    while time.monotonic()<limit and populated(worker)!='0': time.sleep(.005)
    assert populated(worker)=='0'
    for n in ('ready','marker'): (root/n).unlink()
    print('POSITIVE: setsid child marker observed',flush=True)
    # The outside guardian owns the leader and waits for its SIGKILL; it then
    # uses cgroup.kill on the complete worker subtree and reads persistent events.
    p=spawn(TREE,worker,root); waitfile('ready')
    expected='0::'+str(worker).removeprefix('/sys/fs/cgroup')
    assert (root/'ready').read_text().strip()==expected
    assert populated(worker)=='1'
    p.kill(); p.wait(timeout=4)
    kill_cgroup(worker)
    limit=time.monotonic()+4
    while time.monotonic()<limit and populated(worker)!='0': time.sleep(.005)
    if populated(worker)!='0': raise RuntimeError('worker cgroup not empty')
    time.sleep(2.5)
    assert not (root/'marker').exists()
    print('CLEANUP: owner killed; worker populated 0; marker absent',flush=True)
    # This child is directly waitable by the guardian even after its safe move
    # between two task-owned subgroups. Never signal a reaped PID.
    p=spawn(MIGRATE,worker,sibling,root); waitfile('moved')
    expected='0::'+str(sibling).removeprefix('/sys/fs/cgroup')
    assert (root/'moved').read_text().strip()==expected
    assert populated(worker)=='0' and populated(sibling)=='1'
    reap(p)
    print('MIGRATION: same-UID child moved into sibling; worker populated 0',flush=True)
finally:
    for p in processes: reap(p)
    for group in (worker,sibling):
        try: kill_cgroup(group)
        except FileNotFoundError: pass
    for group in (worker,sibling):
        for i in range(100):
            try: group.rmdir(); break
            except OSError:
                time.sleep(.01)
        else: raise RuntimeError('task-owned cgroup removal unresolved: '+str(group))
'''

def run(*args, check=True, timeout=30):
    return subprocess.run(args,text=True,capture_output=True,check=check,timeout=timeout)

with tempfile.TemporaryDirectory(prefix='sfactory-delegated-') as root:
    name='sfactory-'+uuid.uuid4().hex+'.service'
    script=pathlib.Path(root,'manager.py'); script.write_text(MANAGER)
    prior=run('systemctl','--user','show',name,'-p','LoadState','--value',check=False)
    if prior.stdout.strip() not in ('','not-found'): raise RuntimeError('unit exists')
    try:
        result=run('systemd-run','--user','--wait','--pipe','--collect','--unit='+name,
            '--property=Description='+name,'--property=Delegate=yes','--property=RuntimeMaxSec=20s',
            '--property=TimeoutStopSec=3s','/usr/bin/python3',str(script),root,name)
        print(result.stdout,end='')
        if result.stderr: print(result.stderr,end='')
    finally:
        load=run('systemctl','--user','show',name,'-p','LoadState','--value',check=False).stdout.strip()
        if load not in ('','not-found'):
            desc=run('systemctl','--user','show',name,'-p','Description','--value').stdout.strip()
            executable=run('systemctl','--user','show',name,'-p','ExecStart','--value').stdout
            if desc!=name or str(script) not in executable: raise RuntimeError('unit identity unresolved: '+name)
            result=run('systemctl','--user','stop',name,check=False)
            if result.returncode: raise RuntimeError('unit cleanup unresolved: '+name)
print('LIMIT: outer guardian/manager loss, migration outside delegated root, independent identity and durable recovery unproved')
