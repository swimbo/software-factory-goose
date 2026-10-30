"""Review-first activation of the existing canonical independent operator brake."""
import errno,hashlib,json,os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_operator_brake_canary as canary
SYSTEM=pathlib.Path('/etc/systemd/system');ETC=pathlib.Path('/etc/software-factory-goose');STATE=pathlib.Path('/var/lib/software-factory-goose')
G='01M65NEH5T767H8Q5X71TTFR5S'
INTENT=STATE/'canonical-brake-started.json';DONE=STATE/'canonical-brake-ready.json'
UNITS={
 'software-factory-goose-root-stop.service':'05e4d2269d42696cbf2813099e5a75be5ea019c613020672b0964fac669c4f7f',
 'software-factory-goose-root-stop.socket':'e04cc83d65bd2f7712d4c63f46c17ec3b90017e4a514c15499e01f698c57bdba',
 'software-factory-goose-brake.service':'08a835a79442383c893fd0b84eb19a049f1d45d341dec93efb41c880896e1f40',
 'software-factory-goose-brake.socket':'9156dd4f32c175f8576a2658234295fa8154bd6d448f1205a667406026bb245a'}
BINS={'sfactory_root_stop':'99236f262d181442e395a9f706e99856027fab7f069bcb6fefb6950b0c324443','sfactory_brake_frontend':'c18388b4e5b1b26cf986bdb893baff8ce6ecc49f229923ff3075ab1bb95af232','sfctl-registry':'9fd28f105beee4a63d468e14e281f1bffac6a536a7b93a1d55bcebd0dd53d5f7'}
MASK=SYSTEM/'software-factory-goose-root-stop.service.d'/'10-no-docker.conf';MASK_SHA='f9385702a27ae06a58a4b61fbbe6bf6c679d6271074642f2e30176595b08b047'
DROPS={'software-factory-goose-root-stop.service.d':'[Service]\nMemoryMax=128M\nTasksMax=16\nCPUQuota=100%\n','software-factory-goose-brake.service.d':'[Service]\nMemoryMax=256M\nTasksMax=64\nCPUQuota=100%\nEnvironment=TOKIO_WORKER_THREADS=2\n'}

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def prop(unit,key):return old.ctl('show',unit,'-p',key,'--value')
def key_metadata(path,uid,gid,mode):
 st=os.lstat(path);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode),st.st_size)==(uid,gid,1,mode,32),'key metadata invalid')
 try:os.getxattr(path,'system.posix_acl_access',follow_symlinks=False);raise RuntimeError('key ACL present')
 except OSError as e:require(e.errno==errno.ENODATA,'key ACL unavailable')
 return {'dev':st.st_dev,'ino':st.st_ino,'uid':uid,'gid':gid,'mode':mode,'size':st.st_size}
def plan():
 require(os.geteuid()==0 and not os.path.lexists(INTENT) and not os.path.lexists(DONE),'root required or prior attempt')
 old.directory(SYSTEM,0,0,0o755);old.directory(STATE,0,0,0o711);old.directory(ETC,0,0,0o711)
 old.directory(MASK.parent,0,0,0o755);old.read(MASK,0o644,MASK_SHA)
 require({p.name for p in MASK.parent.iterdir()}=={'10-no-docker.conf'},'root stop drop-in collision')
 require(not os.path.lexists(SYSTEM/'software-factory-goose-brake.service.d'),'brake drop-in collision')
 for name,sha in UNITS.items():
  old.read(SYSTEM/name,0o644,sha);require(prop(name,'LoadState')=='loaded' and prop(name,'ActiveState')=='inactive' and prop(name,'Names')==name and prop(name,'FragmentPath')==str(SYSTEM/name) and not prop(name,'Job'),'unit not safely inactive')
  expected=str(MASK) if name=='software-factory-goose-root-stop.service' else ''
  require(prop(name,'DropInPaths')==expected,'unexpected unit drop-in')
 for name,sha in BINS.items():old.read(old.PREFIX/name,0o755,sha,100_000_000)
 keys={'server':key_metadata(ETC/'brake.key',0,2003,0o440),'operator':key_metadata(ETC/'operator-brake.key',1000,1000,0o600)}
 for name in DROPS:require(not os.path.lexists(SYSTEM/name/'20-resources.conf'),'resource drop-in occupied')
 return {'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'units':UNITS,'binaries':BINS,'mask_sha256':MASK_SHA,'keys_metadata':keys,'dropin_sha256':{n:hashlib.sha256(v.encode()).hexdigest() for n,v in DROPS.items()},'status_target':G,'scope':'create resource drop-ins and start only four canonical brake units; no key read by installer'}
def apply(approved):
 require(plan()==approved,'brake activation plan changed')
 old.store(INTENT,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 for name,data in DROPS.items():
  directory=SYSTEM/name
  if not directory.exists():
   os.mkdir(directory,0o755);old.syncdir(SYSTEM)
  old.directory(directory,0,0,0o755);old.store(directory/'20-resources.conf',data.encode(),0o644)
 old.ctl('daemon-reload')
 for name in ('software-factory-goose-root-stop.socket','software-factory-goose-root-stop.service','software-factory-goose-brake.socket','software-factory-goose-brake.service'):old.ctl('start',name)
 for name,sha in UNITS.items():
  old.read(SYSTEM/name,0o644,sha)
  require(prop(name,'ActiveState')=='active' and prop(name,'Names')==name and prop(name,'FragmentPath')==str(SYSTEM/name) and not prop(name,'Job'),'brake unit not active or changed')
 for unit,user in (('software-factory-goose-root-stop.service','root'),('software-factory-goose-brake.service','sfgoose-brake')):
  require(prop(unit,'User')==user and prop(unit,'NoNewPrivileges')=='yes' and prop(unit,'CapabilityBoundingSet')=='','service identity changed')
 require(prop('software-factory-goose-root-stop.service','DropInPaths')==str(MASK)+' '+str(MASK.parent/'20-resources.conf') and prop('software-factory-goose-brake.service','DropInPaths')==str(SYSTEM/'software-factory-goose-brake.service.d'/'20-resources.conf'),'loaded drop-ins differ')
 for name,data in DROPS.items():old.read(SYSTEM/name/'20-resources.conf',0o644,hashlib.sha256(data.encode()).hexdigest())
 require(key_metadata(ETC/'brake.key',0,2003,0o440)==approved['keys_metadata']['server'] and key_metadata(ETC/'operator-brake.key',1000,1000,0o600)==approved['keys_metadata']['operator'],'key metadata changed')
 for unit,mem,tasks in (('software-factory-goose-root-stop.service','134217728','16'),('software-factory-goose-brake.service','268435456','64')):
  require(prop(unit,'MemoryMax')==mem and prop(unit,'TasksMax')==tasks and prop(unit,'CPUQuotaPerSecUSec')=='1s','resource limit not loaded')
 require(canary.preflight_succeeded(prop('software-factory-goose-root-stop.service','ExecStartPre')),'Docker mask preflight failed')
 # systemd switches identity; the CLI alone reads the human key into memory.
 unit='sfactory-canonical-brake-status-'+G.lower()+'.service'
 require(prop(unit,'LoadState')=='not-found','status unit occupied')
 p=canary.run('/usr/bin/systemd-run','--unit='+unit,'--collect','--wait','--pipe','--quiet','--property=User=bo','--property=Group=bo','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=RuntimeMaxSec=15s',str(old.PREFIX/'sfctl-registry'),'--json','private','status',G,'--brake-key-file',str(ETC/'operator-brake.key'),check=False,timeout=20)
 require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'operator status unavailable');status=json.loads(p.stdout)
 require(status.get('target_id')==G and status.get('closed') is True and status.get('frozen') is True and status.get('empty') is True and status.get('engine_reconciled') is False,'status observation mismatch')
 denied=canary.frontend_negative('sfgoose-worker',G)
 require(denied.returncode==0 and ' 403 ' in denied.stdout,'worker denial or key isolation failed')
 result={'boot_id':approved['boot_id'],'status_target':G,'operator_status_verified':True,'worker_denied':True,'engine_reconciled':False,'units_active':True,'key_contents_recorded':False}
 old.store(DONE,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return result
