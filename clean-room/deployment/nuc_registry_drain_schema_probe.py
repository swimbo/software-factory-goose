"""Read only pinned Restate catalog schema via one disposable native UID2000 unit."""
import json,os,pathlib,re,subprocess
import nuc_grant_sidecar_install as old
UNIT='sfactory-registry-drain-schema-20261030.service'
START=old.ETC/'registry-drain-schema-started.json';DONE=old.ETC/'registry-drain-schema-complete.json'
CODE=r'''import http.client,json,os,re
assert (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2000,2000,2000,2000)
s=open('/proc/self/status').read();assert 'NoNewPrivs:\t1' in s and all(('Cap'+x+':\t0000000000000000') in s for x in ('Inh','Prm','Eff','Bnd','Amb'))
names=('sys_invocation','sys_invocation_status','sys_vqueues','sys_vqueue_entry_status')
q="SELECT table_name, column_name FROM information_schema.columns WHERE table_name IN ('sys_invocation','sys_invocation_status','sys_vqueues','sys_vqueue_entry_status') ORDER BY table_name,column_name"
c=http.client.HTTPConnection('127.0.0.1',9070,timeout=10)
c.request('POST','/query',json.dumps({'query':q}),{'Content-Type':'application/json','Accept':'application/json'});r=c.getresponse();raw=r.read(65537);assert r.status==200 and len(raw)<=65536
obj=json.loads(raw);assert set(obj)=={'rows'} and isinstance(obj['rows'],list) and len(obj['rows'])<=512
out={name:[] for name in names}
for row in obj['rows']:
 assert set(row)=={'table_name','column_name'} and row['table_name'] in out and isinstance(row['column_name'],str) and re.fullmatch('[a-z_][a-z_0-9]{0,79}',row['column_name'])
 assert row['column_name'] not in out[row['table_name']];out[row['table_name']].append(row['column_name'])
print(json.dumps({'schema':1,'tables':out},sort_keys=True))'''
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE),'probe already attempted')
 require(old.ctl('show',UNIT,'-p','LoadState','--value')=='not-found','unit occupied')
 paths=subprocess.run(['/usr/bin/systemd-analyze','unit-paths','--system'],env=old.ENV,capture_output=True,timeout=10,check=True).stdout.decode().splitlines();require(paths,'unit paths unavailable')
 stem=UNIT.removesuffix('.service');prefixes=[stem[:i+1] for i,c in enumerate(stem) if c=='-']
 for base in map(pathlib.Path,paths):
  for p in [base/UNIT,base/(UNIT+'.d'),base/'service.d']+[base/(x+'.service.d') for x in prefixes]:require(not os.path.lexists(p),'unit collision')
 return {'unit':UNIT,'sql_scope':'column names only; four invocation and queue tables','writes':'private fixture receipts only'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 args=['/usr/bin/systemd-run','--unit='+UNIT,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf=software-factory-goose-private-net.service','--property=BindsTo=software-factory-goose-private-net.service','--property=After=software-factory-goose-private-net.service','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=128M','--property=TasksMax=32','--property=RuntimeMaxSec=30s','/usr/bin/python3','-I','-B','-c',CODE]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=40,check=False);require(p.returncode==0 and len(p.stdout)<=65536 and len(p.stderr)<=8192,'schema query failed or unknown');out=json.loads(p.stdout)
 require(set(out)=={'schema','tables'} and out['schema']==1 and set(out['tables'])=={'sys_invocation','sys_invocation_status','sys_vqueues','sys_vqueue_entry_status'},'schema result invalid')
 require(old.ctl('show',UNIT,'-p','MainPID','--value')=='0' and old.ctl('show',UNIT,'-p','Job','--value')=='','probe not terminal')
 old.store(DONE,json.dumps(out,sort_keys=True).encode()+b'\n',0o600);return out
