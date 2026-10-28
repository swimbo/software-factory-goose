#!/usr/bin/env python3
"""NUC-only Goose/MCP owner-loss fixture using the existing disposable worker slice."""
import pathlib
import runpy
import subprocess
import sys

here = pathlib.Path(__file__).resolve().parent
base = runpy.run_path(str(here / 'nuc_systemd_docker_recovery_spike.py'))
service = base['SERVICE'].replace(
    'from docker_owner_guardian import DisposableContainer,LABEL',
    'from docker_owner_guardian import DisposableContainer,LABEL,docker\nfrom docker_owned_escape_spike import IMAGE',
)
service = service.replace('ident=owner.prepare()', '''
if owner.closed or owner.ident is not None: raise RuntimeError('owner not fresh')
base='/tmp/sfactory-gate-linux.X4ZjF1LB/goose-build'
mounts=['type=bind,src='+base+'/goose-linux-fixture,dst=/goose,readonly',
        'type=bind,src='+base+'/execution-target/debug/execution,dst=/execution,readonly',
        'type=bind,src='+base+'/fixtures,dst=/fixtures,readonly']
args=['create','--name',owner.name,'--label',LABEL+'='+token,'--cgroup-parent',owner.cgroup_parent,
      '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
      '--pids-limit','128','--memory','1g','--cpus','1','--user','1001:1001',
      '--tmpfs','/work:rw,exec,nosuid,nodev,size=128m,mode=1777']
for mount in mounts:args.extend(['--mount',mount])
args.extend(['--entrypoint','python3','--pull','never',IMAGE,'-B','/fixtures/nuc_goose_mcp_hold.py'])
ident=docker(*args).stdout.strip(); owner.ident=ident
if len(ident)!=64 or any(c not in '0123456789abcdef' for c in ident):raise RuntimeError('invalid owned ID')
obj=owner.inspect(ident)
if obj is None or obj['Config']['User']!='1001:1001' or obj['HostConfig']['NetworkMode']!='none':raise RuntimeError('worker configuration mismatch')
actual={(m['Source'],m['Destination'],m['RW']) for m in obj['Mounts']}
expected={(base+'/goose-linux-fixture','/goose',False),(base+'/execution-target/debug/execution','/execution',False),(base+'/fixtures','/fixtures',False)}
if actual!=expected:raise RuntimeError('worker mount boundary mismatch')
''')
service = service.replace('time.sleep(25)', 'time.sleep(75)')
driver = base['DRIVER'].replace("if 'AFTER_GUARDIAN' in out and 'CGROUP_WRITE_DENIED ' in out:",
                                "if 'GOOSE_MCP_ACTIVE ESCAPED_PROCESS_GROUP' in out:")
driver = driver.replace('deadline=time.monotonic()+8\n   while', 'deadline=time.monotonic()+30\n   while')
driver = driver.replace('--property=RuntimeMaxSec=20s', '--property=RuntimeMaxSec=60s')
driver = driver.replace('PASS: '+"'+MODE+'"+' guardian SIGKILL;',
                        'PASS: '+"'+MODE+'"+' active Goose/MCP with setsid descendant, guardian SIGKILL;')
script = (driver.replace('__MODE__', repr('normal'))
    .replace('__GUARDIAN__', repr(base['guardian']))
    .replace('__MODULE__', repr(base['module']))
    .replace('__SERVICE__', repr(service))
    .replace('__CLEANUP__', repr(base['CLEANUP']))
    .replace('__IMAGE__', repr(base['image'])))
if __name__ == '__main__':
    result = subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],
                            input=script,text=True,timeout=100)
    sys.exit(result.returncode)
