"""Conditional read-only fence for a previously timed-out NUC create."""
import json,subprocess
NAME='sf-owner-224a71d2db764249aa6cade3c1b39c80'
ID='04f7717345b35b6cb6b3c5a2bfdf234c64346e90cc7c3b3c16d6b71eb0e10062'
LABEL='org.software-factory.escape-spike'
TOKEN='224a71d2db764249aa6cade3c1b39c80'
DAEMON='56d25a60-5f64-4212-b904-e750067ac6a5'
PID='2145'
def output(*args):return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10).stdout.decode().strip()
def check():
 if output('/usr/bin/docker','info','--format','{{.ID}}')!=DAEMON or output('/usr/bin/systemctl','show','docker.service','--property=MainPID','--value')!=PID or output('/usr/bin/docker','version','--format','{{.Server.Version}} {{.Server.GitCommit}}')!='29.8.0 3ce5872':raise RuntimeError('original fence daemon changed')
 a=json.loads(output('/usr/bin/docker','inspect',NAME))
 if len(a)!=1:raise RuntimeError('original fence missing')
 x=a[0];s=x['State']
 if x['Id']!=ID or x['Name']!='/'+NAME or x['Config']['Labels'].get(LABEL)!=TOKEN or s['Status']!='created' or s['Running'] or s['Pid']!=0 or s['StartedAt']!='0001-01-01T00:00:00Z':raise RuntimeError('original fence changed')
