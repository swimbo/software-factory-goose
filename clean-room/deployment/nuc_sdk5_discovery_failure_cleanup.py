"""Narrowly stop only retained synthetic discovery units; preserve failure intent."""
import os,pathlib,stat
import nuc_grant_sidecar_install as old
import nuc_registry_offline_backup as backup
import nuc_sdk5_discovery_native_canary as fixture
import nuc_sdk5_discovery_failure_inventory as inventory
START=old.ETC/'sdk5-discovery-failure-cleanup-started.json';DONE=old.ETC/'sdk5-discovery-failure-cleanup-complete.json'
NET_INV='e2354eb81851424b8748b17a3b2b98cf';NET_PID='1597370';SERVER_INV='a18c2d25562e435990539c449be5e263';POS_INV='1bf11262a311421393052a38e89c6d75'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(not any(os.path.lexists(p) for p in (START,DONE)),'cleanup already attempted');ob=inventory.plan();u=ob['units'];net=u[fixture.NET];server=u[fixture.SERVER_UNIT];pos=u[fixture.POS]
 require(net['InvocationID']==NET_INV and net['Job']=='' and ((net['ActiveState']=='active' and net['MainPID']==NET_PID) or (net['ActiveState'] in ('inactive','failed') and net['MainPID']=='0')),'network identity unavailable')
 require(server['InvocationID']==SERVER_INV and server['ActiveState'] in ('inactive','failed') and server['MainPID']=='0' and server['Job']=='' and pos['InvocationID']==POS_INV and pos['MainPID']=='0' and pos['Job']=='' and u[fixture.NEG]['LoadState']=='not-found','original invocation unavailable')
 return {'schema':1,'intent_sha256':ob['intent_sha256'],'network':net,'server':server,'positive':pos,'scope':'stop only exact remaining synthetic network; retain all failure records'}
def apply(approved):
 require(plan()==approved,'cleanup state changed');old.store(START,backup.canonical(approved),0o600)
 if approved['network']['ActiveState']=='active':
  require(old.ctl('show',fixture.NET,'-p','InvocationID','--value')==NET_INV and old.ctl('show',fixture.NET,'-p','MainPID','--value')==NET_PID,'network replaced');old.ctl('stop',fixture.NET)
 for unit in (fixture.NET,fixture.SERVER_UNIT,fixture.POS):
  require(old.ctl('show',unit,'-p','MainPID','--value')=='0' and old.ctl('show',unit,'-p','Job','--value')=='','unit unresolved')
  cg=pathlib.Path('/sys/fs/cgroup/system.slice')/unit
  try:s=os.lstat(cg)
  except FileNotFoundError:continue
  require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'cgroup unresolved')
 result={'schema':1,'intent_sha256':approved['intent_sha256'],'units_empty':True,'failure_retained':True,'retry':False};old.store(DONE,backup.canonical(result),0o600);return result
