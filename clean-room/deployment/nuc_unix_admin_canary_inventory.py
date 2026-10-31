"""Read-only identity inventory of exact active fixture; root receipt only."""
import json,os,pathlib,re
import nuc_grant_sidecar_install as old
import nuc_unix_admin_canary_install as install
import nuc_unix_admin_canary_activate as active
DONE=old.ETC/'unix-admin-canary-process-inventory.json'
def require(v,m):
 if not v:raise RuntimeError(m)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(DONE),'inventory already attempted')
 receipt=json.loads(old.read(active.DONE,0o600));require(receipt.get('fixture_retained_active') is True and receipt.get('production_data_used') is False,'activation unavailable')
 result={}
 for unit,uid in ((install.NET,0),(install.SERVER,2004)):
  p=active.properties(unit);pid=int(p.get('MainPID','0'));require(p.get('ActiveState')=='active' and pid>1 and p.get('Names')==unit and p.get('FragmentPath')==str(old.UNIT/unit) and p.get('DropInPaths','')=='' and p.get('Job','')=='' and p.get('ControlGroup')=='/system.slice/'+unit,'fixture process unavailable')
  inv=old.ctl('show',unit,'-p','InvocationID','--value');require(re.fullmatch(r'[0-9a-f]{32}',inv) is not None,'invocation unavailable')
  data=pathlib.Path('/proc')/str(pid)/'status';raw=data.read_text();require(len(raw)<65536,'status oversized');status={k:v.split() for k,v in (x.split(':',1) for x in raw.splitlines() if ':' in x)}
  require(status.get('Uid')==[str(uid)]*4 and status.get('Gid')==[str(uid)]*4 and all(status.get('Cap'+n)==['0000000000000000'] for n in ('Inh','Prm','Eff','Bnd','Amb')) and status.get('NoNewPrivs')==['1'],'process credentials changed')
  group=pathlib.Path('/sys/fs/cgroup/system.slice')/unit;s=group.stat();require(s.st_uid==0,'cgroup identity unavailable')
  require(active.properties(unit).get('MainPID')==str(pid),'process changed')
  result[unit]={'pid':pid,'invocation_id':inv,'uid':uid,'gid':uid,'caps_empty':True,'no_new_privileges':True,'cgroup_dev':s.st_dev,'cgroup_ino':s.st_ino}
 return {'schema':1,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'units':result,'socket_dev':receipt['journal']['socket_dev'],'socket_ino':receipt['journal']['socket_ino']}
def apply(approved):
 require(plan()==approved,'inventory changed');old.store(DONE,install.canonical(approved)+b'\n',0o600);return approved
