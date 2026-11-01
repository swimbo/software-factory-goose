#!/usr/bin/env python3
"""Unactivated one-shot attestor for the fixed reserved generation.

Root/PID1 are trusted. This checks manager identity and protected installed files;
it does not claim independent /proc/<root-pid>/exe authentication.
"""
import errno, hashlib, json, os, pathlib, re, stat, sys
import nuc_grant_sidecar_install as old
import nuc_evidence_reader_canary as protected

G='01M65RMR3F04YB1B016EBBSXGG'
TASK='01M65RMR3FE6FQTFRBHERRHXRG'
ROOT=old.ETC/'finalization'
CONFIG=ROOT/(G+'.runtime.json')
MANIFEST=ROOT/(G+'.process.json')
INTENT=ROOT/(G+'.process-intent.json')
SOCKET=old.RUN/'root-finalization'/(G+'.sock')
SERVICE='software-factory-goose-root-finalization@'+G+'.service'
SOCKET_UNIT='software-factory-goose-root-finalization@'+G+'.socket'
SERVICE_TEMPLATE=old.UNIT/'software-factory-goose-root-finalization@.service'
SOCKET_TEMPLATE=old.UNIT/'software-factory-goose-root-finalization@.socket'
BINARY=old.PREFIX/'root_finalization_runtime'
ANCHOR='software-factory-goose-private-net.service'
ANCHOR_BINARY=old.PREFIX/'private-netns-anchor.py'
ANCHOR_UNIT=old.UNIT/ANCHOR
ANCHOR_DROPIN=old.UNIT/'software-factory-goose-private-net.service.d/50-resources.conf'
ANCHOR_BINARY_SHA='3eb0162f005b961be44c381e142d16dc7ded34b2d5eca81ab9f7373fc1858123'
ANCHOR_UNIT_SHA='cc52bf8108541f2b8b57ab2c2c8eb150ec803127d06d6dda6dc93de1252f5727'
ANCHOR_DROPIN_SHA='5b0837ce1d36545db58ad6767023256a7fc7c2465d13d15c495b0c0e39e5670b'
BINARY_SHA='28e2c9ab06d8f5286cd2529562fccd15e8a41eb22214ed5a63f6c3b2beeb32f3'
SERVICE_SHA='a069f3fbc07e5240cf73cdb275f34848bc3daee09eded912ef4a10bed9ff36d5'
SOCKET_SHA='6418eb231f7950cb8f29ce6c321553d48c1e96f959f5667e337b1224c67a8dd9'

def properties(unit):
    raw=old.ctl('show',unit,'--property=LoadState,ActiveState,SubState,MainPID,InvocationID,Names,FragmentPath,DropInPaths,User,Group,NoNewPrivileges,CapabilityBoundingSet,PrivateNetwork,BindsTo,JoinsNamespaceOf,ExecStart,Job','--all','--no-pager')
    values={}
    for line in raw.splitlines():
        key,sep,value=line.partition('=');old.require(sep and key not in values,'ambiguous systemd property');values[key]=value
    return values

def strict_json(raw):
    def unique(pairs):
        result={}
        for key,value in pairs:
            old.require(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid number')))

def plan(*,after_intent=False):
    old.require(os.geteuid()==0 and os.getegid()==0 and (after_intent or not os.path.lexists(INTENT)) and not os.path.lexists(MANIFEST),'attestation unavailable')
    old.directory(ROOT,0,0,0o755)
    old.directory(SOCKET.parent,0,1000,0o710)
    for path,mode,digest,limit in [(BINARY,0o755,BINARY_SHA,100_000_000),(SERVICE_TEMPLATE,0o644,SERVICE_SHA,65536),(SOCKET_TEMPLATE,0o644,SOCKET_SHA,65536),(ANCHOR_BINARY,0o755,ANCHOR_BINARY_SHA,65536),(ANCHOR_UNIT,0o644,ANCHOR_UNIT_SHA,65536),(ANCHOR_DROPIN,0o644,ANCHOR_DROPIN_SHA,65536)]:
        protected.ancestors(path);old.read(path,mode,digest,limit)
    protected.ancestors(CONFIG)
    raw=old.read(CONFIG,0o600);cfg=strict_json(raw);boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    private=strict_json(old.read(old.RUN/'private-netns.json',0o600));host=strict_json(old.read(old.RUN/'host-netns.json',0o600))
    old.require(cfg['schema']==1 and cfg['generation']==G and cfg['scope']['generation']==G and cfg['scope']['task_id']==TASK and cfg['boot_id']==boot,'scope mismatch')
    old.require(private['role']=='private' and private['uid']==0 and private['version']==1 and host['role']=='host' and host['uid']==0 and host['version']==1 and (private['netns_dev'],private['netns_ino'])==(cfg['namespace_dev'],cfg['namespace_ino']) and (host['netns_dev'],host['netns_ino'])==(cfg['host_namespace_dev'],cfg['host_namespace_ino']) and (private['netns_dev'],private['netns_ino'])!=(host['netns_dev'],host['netns_ino']),'namespace scope mismatch')
    p=properties(SERVICE);a=properties(ANCHOR);s=properties(SOCKET_UNIT)
    expected={'LoadState':'loaded','ActiveState':'active','Names':SERVICE,'FragmentPath':str(SERVICE_TEMPLATE),'DropInPaths':'','User':'root','Group':'root','NoNewPrivileges':'yes','CapabilityBoundingSet':'','PrivateNetwork':'yes','BindsTo':ANCHOR,'JoinsNamespaceOf':ANCHOR,'Job':''}
    old.require(all(p.get(k)==v for k,v in expected.items()) and re.fullmatch('[0-9]+',p.get('MainPID','')) and int(p['MainPID'])>0 and re.fullmatch('[0-9a-f]{32}',p.get('InvocationID','')),'service identity mismatch')
    old.require(p.get('ExecStart','').startswith('{ path='+str(BINARY)+' ; argv[]='+str(BINARY)+' '+G+' ; ignore_errors=no ;') and p['ExecStart'].count('{ path=')==1,'service command mismatch')
    anchor_expected={'LoadState':'loaded','ActiveState':'active','Names':ANCHOR,'FragmentPath':str(ANCHOR_UNIT),'DropInPaths':str(ANCHOR_DROPIN),'User':'root','NoNewPrivileges':'yes','CapabilityBoundingSet':'','PrivateNetwork':'yes'}
    old.require(all(a.get(k)==v for k,v in anchor_expected.items()) and a.get('MainPID')==str(private['pid']) and re.fullmatch('[0-9a-f]{32}',a.get('InvocationID','')) and a.get('ExecStart','').startswith('{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+str(ANCHOR_BINARY)+' private ; ignore_errors=no ;') and a['ExecStart'].count('{ path=')==1,'anchor identity mismatch')
    old.require(s.get('LoadState')=='loaded' and s.get('ActiveState')=='active' and s.get('Names')==SOCKET_UNIT and s.get('FragmentPath')==str(SOCKET_TEMPLATE) and s.get('DropInPaths')=='','socket unit mismatch')
    st=SOCKET.lstat();old.require(stat.S_ISSOCK(st.st_mode) and st.st_uid==0 and st.st_gid==1000 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o660,'socket metadata mismatch')
    try:os.getxattr(SOCKET,'system.posix_acl_access',follow_symlinks=False)
    except OSError as exc:old.require(exc.errno==errno.ENODATA,'socket ACL unavailable')
    else:raise RuntimeError('socket ACL present')
    # Recheck manager identities and socket inode before the caller can publish.
    after=properties(SERVICE);anchor_after=properties(ANCHOR);st2=SOCKET.lstat()
    old.require((after.get('MainPID'),after.get('InvocationID'),after.get('ActiveState'))==(p['MainPID'],p['InvocationID'],'active') and (anchor_after.get('MainPID'),anchor_after.get('InvocationID'),anchor_after.get('ActiveState'))==(a['MainPID'],a['InvocationID'],'active') and (st2.st_dev,st2.st_ino)==(st.st_dev,st.st_ino),'identity changed during attestation')
    return {'schema':1,'generation':G,'boot_id':boot,'service_unit':SERVICE,'socket_unit':SOCKET_UNIT,'main_pid':int(p['MainPID']),'invocation_id':p['InvocationID'],'exec_start':p['ExecStart'],'binary_sha256':BINARY_SHA,'service_unit_sha256':SERVICE_SHA,'socket_unit_sha256':SOCKET_SHA,'fragment_path':str(SERVICE_TEMPLATE),'drop_in_paths':[],'private_namespace_dev':private['netns_dev'],'private_namespace_ino':private['netns_ino'],'anchor_unit':ANCHOR,'anchor_main_pid':int(a['MainPID']),'anchor_invocation_id':a['InvocationID'],'socket_dev':st.st_dev,'socket_ino':st.st_ino,'bootstrap_sha256':hashlib.sha256(raw).hexdigest()}

def packed(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
def apply(reviewed):
    old.require(plan()==reviewed,'attestation state changed')
    old.store(INTENT,packed(reviewed),0o600)
    old.require(plan(after_intent=True)==reviewed,'attestation changed after intent')
    old.store(MANIFEST,packed(reviewed),0o444)
    return {'manifest_sha256':hashlib.sha256(packed(reviewed)).hexdigest(),'generation':G,'approval':False}

if __name__=='__main__':
    if sys.argv==[sys.argv[0],'plan']:
        value=plan();print(json.dumps({'plan':value,'sha256':hashlib.sha256(packed(value)).hexdigest()},sort_keys=True))
    elif len(sys.argv)==3 and sys.argv[1]=='apply':
        value=plan();old.require(sys.argv[2]==hashlib.sha256(packed(value)).hexdigest(),'reviewed plan digest mismatch');print(json.dumps(apply(value),sort_keys=True))
    else:raise RuntimeError('expected plan or apply with exact plan digest')
