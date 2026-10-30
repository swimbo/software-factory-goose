"""One-shot root binding of the live real-sidecar process to reviewed systemd state."""
import hashlib,json,os,pathlib,re,stat
import nuc_grant_sidecar_install as old
import nuc_registry_sidecar_install as install
import nuc_registry_sidecar_activate as active
ATTEST=old.ETC/'registry-process-attestation.json';START=old.ETC/'registry-process-attestation-started.json'
ANCHOR_UNIT='software-factory-goose-private-net.service';ANCHOR='/usr/local/libexec/software-factory-goose/private-netns-anchor.py'
ANCHOR_SHA='3eb0162f005b961be44c381e142d16dc7ded34b2d5eca81ab9f7373fc1858123'
ANCHOR_UNIT_SHA='cc52bf8108541f2b8b57ab2c2c8eb150ec803127d06d6dda6dc93de1252f5727'
DROPIN='/etc/systemd/system/software-factory-goose-private-net.service.d/50-resources.conf'
DROPIN_SHA='5b0837ce1d36545db58ad6767023256a7fc7c2465d13d15c495b0c0e39e5670b'
CONFIG_SHA='58a1d4f04a2a8ffe98424bd6e8c29b8a4491faac53346698e4f715017df04e78'
UNIT_SHA='4d96129f56640cc5be89817901dd6703a0aa1951fc5de939c01799329c62c4c2'

def require(value,msg):
 if not value:raise RuntimeError(msg)
def ticks(pid):
 raw=pathlib.Path(f'/proc/{pid}/stat').read_text();require(len(raw)<8192 and ')' in raw,'process stat unavailable');return int(raw.rsplit(')',1)[1].split()[19])
def process_status(pid,uid,gid):
 text=pathlib.Path(f'/proc/{pid}/status').read_text();require(len(text)<65536,'process status oversized')
 values={k:v.split() for k,v in (line.split(':',1) for line in text.splitlines() if ':' in line)}
 require(values.get('Uid')==[str(uid)]*4 and values.get('Gid')==[str(gid)]*4 and values.get('CapEff')==['0000000000000000'] and values.get('NoNewPrivs')==['1'],'process identity mismatch')

def properties(unit):
 out=old.ctl('show',unit,'--property=LoadState,ActiveState,MainPID,Names,FragmentPath,DropInPaths,User,Group,NoNewPrivileges,CapabilityBoundingSet,PrivateNetwork,BindsTo,JoinsNamespaceOf,ExecStartPre,ExecStartPost,Environment,EnvironmentFiles,ControlGroup,ExecStart','--all','--no-pager')
 return dict(line.split('=',1) for line in out.splitlines())
def plan():
 require(os.geteuid()==0 and not os.path.lexists(ATTEST) and not os.path.lexists(START),'attestation already attempted')
 for p,d,m,maxsize in [(install.BIN,install.SOURCE_SHA,0o755,100_000_000),(old.UNIT/(install.NAME+'runtime.service'),UNIT_SHA,0o644,65536),(install.MANIFEST,CONFIG_SHA,0o644,65536),(pathlib.Path(ANCHOR),ANCHOR_SHA,0o755,65536),(old.UNIT/ANCHOR_UNIT,ANCHOR_UNIT_SHA,0o644,65536),(pathlib.Path(DROPIN),DROPIN_SHA,0o644,65536)]:old.read(p,m,d,maxsize)
 completed=json.loads(old.read(active.DONE,0o600));running=active.service_running();require(completed['sidecar']==running and completed['task_submitted'] is False and completed['engine_enabled'] is False,'activation identity mismatch')
 cfg=json.loads(old.read(install.CFG,0o644,'d413213318a6555c62fc24ffa848c1dda42db510d92a1160c6f86f20a803b23b'));private=json.loads(old.read(old.RUN/'private-netns.json',0o600));host=json.loads(old.read(old.RUN/'host-netns.json',0o600))
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();require(cfg['boot_id']==boot and private['role']=='private' and private['uid']==0 and private['version']==1 and host['role']=='host' and host['uid']==0 and host['version']==1 and (private['netns_dev'],private['netns_ino'])==(cfg['namespace_dev'],cfg['namespace_ino']) and (host['netns_dev'],host['netns_ino'])==(cfg['host_namespace_dev'],cfg['host_namespace_ino']) and (host['netns_dev'],host['netns_ino'])!=(private['netns_dev'],private['netns_ino']),'anchor namespace mismatch')
 p=properties(install.NAME+'runtime.service');a=properties(ANCHOR_UNIT)
 expected={'LoadState':'loaded','ActiveState':'active','Names':install.NAME+'runtime.service','FragmentPath':str(old.UNIT/(install.NAME+'runtime.service')),'DropInPaths':'','User':'sfgoose-control','Group':'sfgoose-control','NoNewPrivileges':'yes','CapabilityBoundingSet':'','PrivateNetwork':'yes','BindsTo':ANCHOR_UNIT,'JoinsNamespaceOf':ANCHOR_UNIT,'ExecStartPre':'','ExecStartPost':'','Environment':'','EnvironmentFiles':'','ControlGroup':'/system.slice/'+install.NAME+'runtime.service'}
 require(all(p.get(k, '' if k in ('ExecStartPre','ExecStartPost','EnvironmentFiles') else None)==v for k,v in expected.items()) and p.get('MainPID')==str(running['pid']),'service properties changed')
 require(a.get('LoadState')=='loaded' and a.get('ActiveState')=='active' and a.get('Names')==ANCHOR_UNIT and a.get('FragmentPath')==str(old.UNIT/ANCHOR_UNIT) and a.get('DropInPaths')==DROPIN and a.get('MainPID')==str(private['pid']) and a.get('User')=='root' and a.get('NoNewPrivileges')=='yes' and a.get('CapabilityBoundingSet')=='' and a.get('PrivateNetwork')=='yes','anchor properties changed')
 require(p.get('ExecStart','').startswith('{ path='+str(install.BIN)+' ; argv[]='+str(install.BIN)+' ; ignore_errors=no ;') and p['ExecStart'].count('{ path=')==1,'real ExecStart changed')
 require(a.get('ExecStart','').startswith('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+ANCHOR+' private ; ignore_errors=no ;') and a['ExecStart'].count('{ path=')==1,'anchor ExecStart changed')
 sock=running['sockets']['registry-launch-grant.sock'];pid=running['pid'];anchor=private['pid'];process_status(pid,2000,2000);process_status(anchor,0,0)
 binding={'schema':1,'boot_id':boot,'pid':pid,'start_ticks':ticks(pid),'binary_sha256':install.SOURCE_SHA,'unit_sha256':UNIT_SHA,'config_sha256':CONFIG_SHA,'netns_dev':private['netns_dev'],'netns_ino':private['netns_ino'],'cgroup_dev':running['cgroup_dev'],'cgroup_ino':running['cgroup_ino'],'socket_dev':sock['dev'],'socket_ino':sock['ino'],'anchor_pid':anchor,'anchor_start_ticks':ticks(anchor),'anchor_unit_sha256':ANCHOR_UNIT_SHA,'anchor_binary_sha256':ANCHOR_SHA,'anchor_dropin_sha256':DROPIN_SHA}
 require(properties(install.NAME+'runtime.service').get('MainPID')==str(pid) and properties(ANCHOR_UNIT).get('MainPID')==str(anchor) and ticks(pid)==binding['start_ticks'] and ticks(anchor)==binding['anchor_start_ticks'],'process changed during inspection')
 return binding

def apply(approved):
 require(plan()==approved,'attestation plan changed');old.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 old.store(ATTEST,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 return {'manifest_sha256':hashlib.sha256(json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n').hexdigest(),'service_pid':approved['pid'],'grant_requested':False}
