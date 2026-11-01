"""Read-only design/identity preflight; deliberately exposes no activation action."""
import hashlib,os,pathlib,re,stat,subprocess
import nuc_evidence_reader_canary as guard
import nuc_root_finalization_attest as attest
import nuc_root_finalization_prepare as prep

ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C'}
def plan():
    old=prep.old;guard.require(os.geteuid()==0 and os.getegid()==0,'root required')
    for path,mode,digest,limit in ((attest.BINARY,0o755,attest.BINARY_SHA,100_000_000),(attest.SERVICE_TEMPLATE,0o644,attest.SERVICE_SHA,65536),(attest.SOCKET_TEMPLATE,0o644,attest.SOCKET_SHA,65536),(attest.ANCHOR_BINARY,0o755,attest.ANCHOR_BINARY_SHA,65536),(attest.ANCHOR_UNIT,0o644,attest.ANCHOR_UNIT_SHA,65536),(attest.ANCHOR_DROPIN,0o644,attest.ANCHOR_DROPIN_SHA,65536)):
        guard.ancestors(path);old.read(path,mode,digest,limit)
    old.directory(attest.SOCKET.parent,0,1000,0o710)
    guard.require(not os.path.lexists(attest.SOCKET) and not os.path.lexists(attest.MANIFEST) and not os.path.lexists(attest.INTENT),'socket or attestation already occupied')
    raw=old.read(attest.CONFIG,0o600);cfg=attest.strict_json(raw);boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    private=attest.strict_json(old.read(old.RUN/'private-netns.json',0o600));host=attest.strict_json(old.read(old.RUN/'host-netns.json',0o600))
    guard.require(cfg['schema']==1 and cfg['generation']==attest.G and cfg['scope']['task_id']==attest.TASK and cfg['scope']['generation']==attest.G and cfg['boot_id']==boot,'scope or boot mismatch')
    guard.require(private['role']=='private' and private['uid']==0 and private['version']==1 and host['role']=='host' and host['uid']==0 and host['version']==1 and (private['netns_dev'],private['netns_ino'])==(cfg['namespace_dev'],cfg['namespace_ino']) and (host['netns_dev'],host['netns_ino'])==(cfg['host_namespace_dev'],cfg['host_namespace_ino']) and (private['netns_dev'],private['netns_ino'])!=(host['netns_dev'],host['netns_ino']),'namespace metadata mismatch')
    a=attest.properties(attest.ANCHOR);expected={'LoadState':'loaded','ActiveState':'active','Names':attest.ANCHOR,'FragmentPath':str(attest.ANCHOR_UNIT),'DropInPaths':str(attest.ANCHOR_DROPIN),'User':'root','NoNewPrivileges':'yes','CapabilityBoundingSet':'','PrivateNetwork':'yes'}
    guard.require(all(a.get(k)==v for k,v in expected.items()) and not a.get('Job') and a.get('MainPID')==str(private['pid']) and re.fullmatch('[0-9a-f]{32}',a.get('InvocationID','')) and a.get('ExecStart','').startswith('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+str(attest.ANCHOR_BINARY)+' private ; ignore_errors=no ;') and a['ExecStart'].count('{ path=')==1,'anchor identity mismatch')
    authorization=old.ETC/'finalization-authorization'
    old.directory(authorization,0,0,0o755)
    lock=authorization/(attest.G+'.lock');fd=os.open(lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        st=os.fstat(fd);guard.require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_gid==2000 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o440,'authorization lock mismatch');old.noacl(fd)
    finally:os.close(fd)
    guard.require(not any(os.path.lexists(authorization/(attest.G+suffix)) for suffix in ('.pending','.authorization.json','.complete.json')),'authorization state occupied')
    for unit in (attest.SERVICE,attest.SOCKET_UNIT):
        p=attest.properties(unit);guard.require(p.get('ActiveState')=='inactive' and p.get('MainPID','0') in ('','0') and not p.get('Job'),'unit not inactive')
    paths=subprocess.run(['/usr/bin/systemd-analyze','--system','unit-paths'],env=ENV,capture_output=True,timeout=5,check=True).stdout.decode().splitlines();guard.require(paths and len(paths)<=64 and all(pathlib.Path(p).is_absolute() for p in paths),'unit paths unavailable')
    for unit in (attest.SERVICE,attest.SOCKET_UNIT):
        prefix=unit.rsplit('@',1)[0]+'@';kind='service' if unit.endswith('.service') else 'socket';candidates=[unit+'.d',prefix+'.'+kind+'.d',kind+'.d']+[unit[:i+1]+'.'+kind+'.d' for i,c in enumerate(unit.split('@',1)[0]) if c=='-']
        for parent in paths:
            for name in candidates:guard.require(not os.path.lexists(pathlib.Path(parent)/name),'unit drop-in occupied')
    return {'schema':1,'purpose':'review-only-root-finalization-activation-plan','generation':attest.G,'boot_id':boot,'bootstrap_sha256':hashlib.sha256(raw).hexdigest(),'runtime_sha256':attest.BINARY_SHA,'service_sha256':attest.SERVICE_SHA,'socket_sha256':attest.SOCKET_SHA,'private_namespace_dev':private['netns_dev'],'private_namespace_ino':private['netns_ino'],'anchor_pid':private['pid'],'anchor_invocation_id':a['InvocationID'],'planned_actions':['daemon-reload','start fixed generation socket','start fixed generation service','post-start attestation'],'execution_permitted':False,'sdk5_ingress_admission_required':True,'publication':False}
