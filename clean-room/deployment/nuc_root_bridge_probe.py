#!/usr/bin/env python3
"""Read-only root-bridge prerequisite probe; creates only its own bridge."""
import pathlib,runpy,subprocess,sys
p=pathlib.Path(__file__).with_name('nuc_barrier_canary.py');m=runpy.run_path(str(p))
ROOT=r'''import json,os,subprocess
E={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','SYSTEMD_IN_CHROOT':'0'}
r=subprocess.run(['/usr/bin/systemctl','show','docker.service','-p','MainPID','-p','ActiveState','--value'],capture_output=True,text=True,timeout=10,env=E)
if r.returncode:
 print('PROBE_ERROR '+json.dumps({'systemctl_code':r.returncode,'stderr':r.stderr[:1024]}),flush=True);raise RuntimeError('systemd probe failed')
values=r.stdout.splitlines()
if '2145' not in values or 'active' not in values:raise RuntimeError('daemon unit identity changed')
d=['/usr/bin/docker','--host','unix:///run/docker.sock']; info=json.loads(subprocess.check_output(d+['info','--format','{{json .}}'],text=True,timeout=10,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'}))
o=json.loads(subprocess.check_output(d+['inspect','04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062'],text=True,timeout=10,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'}))[0]
if info.get('ID')!='56d25a60-5f64-4212-b904-e750067ac6a5' or o['Id']!='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062' or o['Name']!='/sf-owner-224a71d2db764249aa6cade3c1b39c80' or o['State']['Status']!='created' or o['State']['Pid']!=0:raise RuntimeError('original guard changed')
print('RESULT '+json.dumps({'state':'probe_passed','probe':'systemd_manager_and_original_readonly','daemon_pid':'2145'}),flush=True)
'''
source=m['REMOTE'].replace('canary_passed','probe_passed').replace('canary_failed','probe_failed').replace('__ROOT_SCRIPT__',repr(ROOT));compile(source,'<remote>','exec');compile(ROOT,'<root>','exec')
if __name__=='__main__':
 result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hermes-control','python3','-'],input=source,text=True,timeout=60)
 sys.exit(result.returncode)
