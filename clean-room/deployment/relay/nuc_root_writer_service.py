#!/usr/bin/python3
"""Root-owned per-generation broker candidate. Not installed or activated."""
import ctypes
import json
import pathlib
import hashlib
import os
import re
import selectors
import socket
import stat
import struct
import subprocess
import sys
import time
sys.path.insert(0,os.path.dirname(os.path.realpath(__file__)))
from nuc_relay_authority import Denied, _no_acl, _root_bytes, load_root_scope
from nuc_relay_stream import no_duplicates
from nuc_root_writer_broker import WriterBroker
from nuc_writer_binding import load_writer_binding

ROOT='/var/lib/software-factory-goose/stop'
ETC='/etc/software-factory-goose'
HANDOFF='/var/lib/software-factory-goose/handoff'
CG='/sys/fs/cgroup'


def safe_dir(path,owner=0,group=0,mode=None):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=owner or st.st_gid!=group or st.st_mode&0o022
                or (mode is not None and stat.S_IMODE(st.st_mode)!=mode)):
            raise Denied('directory unavailable')
        _no_acl(fd,True)
        return fd
    except Exception:
        os.close(fd);raise


def cgroup2_dir(generation,task):
    """Open the exact root-owned cgroup2 inode; cgroupfs does not implement ACLs."""
    if sys.platform!='linux' or os.uname().machine!='x86_64' or not re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',generation):raise Denied('cgroup unavailable')
    path=CG+'/sfactory'+generation.lower()+'.slice'
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd);buf=ctypes.create_string_buffer(256);libc=ctypes.CDLL(None,use_errno=True)
        if libc.fstatfs(fd,ctypes.byref(buf))!=0:raise Denied('cgroup unavailable')
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_mode&0o022
                or (st.st_dev,st.st_ino)!=(task.get('cgroup_dev'),task.get('cgroup_ino'))
                or ctypes.c_long.from_buffer(buf).value!=0x63677270):raise Denied('cgroup unavailable')
        return fd
    except Exception:
        os.close(fd);raise


def child_file(directory,name):
    return os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=directory)


def inspect_bifrost(binding):
    binary=os.stat('/usr/bin/docker',follow_symlinks=False)
    daemon=os.stat('/run/docker.sock',follow_symlinks=False)
    if (not stat.S_ISREG(binary.st_mode) or binary.st_uid!=0 or binary.st_mode&0o022
            or not stat.S_ISSOCK(daemon.st_mode) or daemon.st_uid!=0):raise Denied('provider unavailable')
    args=['/usr/bin/docker','--host','unix:///run/docker.sock','--config','/run/software-factory-goose/docker-empty-config','inspect','--format','{{.Id}} {{.Image}} {{.State.Pid}} {{.State.Status}} {{.NetworkSettings.SandboxKey}}',binding['container_id']]
    proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'},close_fds=True)
    try:
        os.set_blocking(proc.stdout.fileno(),False);selector=selectors.DefaultSelector()
        try:
            selector.register(proc.stdout,selectors.EVENT_READ);data=bytearray();deadline=time.monotonic()+5
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:raise Denied('provider unavailable')
                for key,_ in selector.select(remaining):
                    chunk=os.read(key.fd,4097-len(data))
                    if not chunk:selector.unregister(proc.stdout);break
                    data.extend(chunk)
                    if len(data)>4096:raise Denied('provider unavailable')
            if proc.wait(timeout=max(.01,deadline-time.monotonic()))!=0:raise Denied('provider unavailable')
        finally:selector.close()
    finally:
        if proc.poll() is None:proc.kill();proc.wait()
        proc.stdout.close()
    expected=f"{binding['container_id']} {binding['image_id']} {binding['pid']} running {binding['sandbox_key']}\n".encode()
    if bytes(data)!=expected:raise Denied('provider unavailable')
    ns=os.stat(binding['sandbox_key'])
    if (ns.st_dev,ns.st_ino)!=(binding['network_device'],binding['network_inode']):raise Denied('provider unavailable')


def inspect_writer(binding):
    """Inspect only the root-sealed writer ID; never execute inside a container."""
    args=['/usr/bin/docker','--host','unix:///run/docker.sock','--config','/run/software-factory-goose/docker-empty-config',
          'inspect','--format','{{json .}}',binding['writer_container_id']]
    proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'},close_fds=True)
    try:
        os.set_blocking(proc.stdout.fileno(),False);selector=selectors.DefaultSelector()
        try:
            selector.register(proc.stdout,selectors.EVENT_READ);data=bytearray();deadline=time.monotonic()+5
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:raise Denied('writer unavailable')
                for key,_ in selector.select(remaining):
                    chunk=os.read(key.fd,1024*1024+1-len(data))
                    if not chunk:selector.unregister(proc.stdout);break
                    data.extend(chunk)
                    if len(data)>1024*1024:raise Denied('writer unavailable')
            if proc.wait(timeout=max(.01,deadline-time.monotonic()))!=0:raise Denied('writer unavailable')
        finally:selector.close()
    finally:
        if proc.poll() is None:proc.kill();proc.wait()
        proc.stdout.close()
    try:obj=json.loads(data,object_pairs_hook=no_duplicates)
    except Exception:raise Denied('writer unavailable') from None
    return validate_writer_inspect(obj,binding)


def validate_writer_inspect(obj,binding):
    try:
        config=obj['Config'];host=obj['HostConfig'];state=obj['State'];pid=state['Pid']
        if (obj['Id']!=binding['writer_container_id'] or obj['Image']!='sha256:'+binding['writer_image_sha256']
                or state['Status']!='running' or type(pid) is not int or pid<=0
                or config['User']!='2001:2001' or host['NetworkMode']!='none'
                or host['ReadonlyRootfs'] is not True or host['Privileged'] is not False
                or host['CapDrop']!=['ALL'] or host.get('CapAdd') not in (None,[])
                or host.get('RestartPolicy',{}).get('Name')!='no'
                or not any(item in ('no-new-privileges','no-new-privileges:true') for item in host.get('SecurityOpt',[]))
                or config.get('Entrypoint')!=['/usr/local/bin/python3','-I','-B','/factory/nuc_fixed_writer.py']
                or config.get('Cmd') not in (None,[])):
            raise Denied('writer unavailable')
        mounts=obj['Mounts']
        normalized=[]
        for m in mounts:
            if not isinstance(m,dict) or m.get('Type')!='bind' or type(m.get('RW')) is not bool:raise Denied('writer unavailable')
            normalized.append({'source':m['Source'],'destination':m['Destination'],'rw':m['RW']})
        normalized.sort(key=lambda m:m['destination'])
        expected=[{'source':binding['candidate_dir']['path'],'destination':'/candidate','rw':True},
                  {'source':binding['input_dir']['path'],'destination':'/handoff/input','rw':False},
                  {'source':binding['output_dir']['path'],'destination':'/handoff/output','rw':True}]
        if normalized!=expected:raise Denied('writer unavailable')
        canonical=json.dumps(normalized,sort_keys=True,separators=(',',':')).encode()
        if hashlib.sha256(canonical).hexdigest()!=binding['mounts_sha256']:raise Denied('writer unavailable')
        with open('/proc/'+str(pid)+'/cgroup','rt',encoding='ascii') as f:cg=f.read(4097)
        lines=cg.splitlines()
        if len(cg)>4096 or len(lines)!=1 or not lines[0].startswith('0::/') or 'sfactory'+binding['generation'].lower()+'.slice' not in lines[0][4:].split('/'):
            raise Denied('writer unavailable')
        return pid
    except Denied:raise
    except Exception:raise Denied('writer unavailable') from None


def verify_deadline_records(generation, scope, task, armed_raw, grant_raw, now_ms, now_mono_ns):
    try:
        armed=json.loads(armed_raw,object_pairs_hook=no_duplicates)
        verified=json.loads(grant_raw,object_pairs_hook=no_duplicates)
        required={'schema','target','boot_id','binding_sha256','verified_grant_sha256','wake_monotonic_ns','expiry_ms','engine_effects'}
        if not isinstance(armed,dict) or set(armed)!=required or type(armed['schema']) is not int or armed['schema']!=1 or armed['target']!=generation or armed['boot_id']!=task['boot_id'] or armed['binding_sha256']!=scope['grant_sha256'] or armed['verified_grant_sha256']!=hashlib.sha256(grant_raw).hexdigest() or armed['engine_effects'] is not False:
            raise Denied('deadline unavailable')
        if (not isinstance(verified,dict) or set(verified)!={'schema','generation','binding_sha256','reservation'} or type(verified['schema']) is not int or verified['schema']!=1 or verified['generation']!=generation or verified['binding_sha256']!=scope['grant_sha256']):
            raise Denied('deadline unavailable')
        grant=verified['reservation']
        if (not isinstance(grant,dict) or grant.get('generation')!=generation or not isinstance(grant.get('scope'),dict) or grant['scope'].get('generation')!=generation or grant['scope'].get('task_id')!=scope['task_id'] or type(grant.get('expires_at_ms')) is not int or type(grant.get('hard_deadline_ms')) is not int or grant['expires_at_ms']!=armed['expiry_ms'] or grant['expires_at_ms']>grant['hard_deadline_ms']):
            raise Denied('deadline unavailable')
        if (type(armed['wake_monotonic_ns']) is not int or type(armed['expiry_ms']) is not int or type(now_ms) is not int or type(now_mono_ns) is not int or not 0<now_mono_ns<armed['wake_monotonic_ns'] or not 0<now_ms<armed['expiry_ms']):
            raise Denied('deadline unavailable')
    except Denied:raise
    except Exception:raise Denied('deadline unavailable') from None


def read_deadline_file(state_fd,name):
    fd=child_file(state_fd,name)
    try:return _root_bytes(fd,16384)
    finally:os.close(fd)


class HostAuthority:
    def __init__(self,generation,scope,binding,writer_binding,task,state_fd,cgroup_fd):
        self.g=generation;self.scope=scope;self.binding=binding;self.task=task
        self.writer_binding=writer_binding;self.writer_pid=None
        self.state_fd=state_fd;self.cgroup_fd=cgroup_fd
    def check_stop(self):
        try:
            try:os.stat(self.g+'.closed',dir_fd=self.state_fd,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise Denied('generation closed')
            armed_raw=read_deadline_file(self.state_fd,self.g+'.deadline-armed.json')
            grant_raw=read_deadline_file(self.state_fd,self.g+'.grant-verified')
            verify_deadline_records(self.g,self.scope,self.task,armed_raw,grant_raw,time.time_ns()//1_000_000,time.monotonic_ns())
            boot=open('/proc/sys/kernel/random/boot_id','rt',encoding='ascii').read(128).strip()
            st=os.fstat(self.cgroup_fd)
            named=os.stat(CG+'/sfactory'+self.g.lower()+'.slice',follow_symlinks=False)
            if (boot!=self.task['boot_id'] or not stat.S_ISDIR(named.st_mode)
                    or (st.st_dev,st.st_ino)!=(self.task['cgroup_dev'],self.task['cgroup_ino'])
                    or (named.st_dev,named.st_ino)!=(st.st_dev,st.st_ino)):
                raise Denied('generation unavailable')
            fd=child_file(self.cgroup_fd,'cgroup.freeze')
            try:freeze=os.read(fd,32)
            finally:os.close(fd)
            fd=child_file(self.cgroup_fd,'cgroup.events')
            try:events=os.read(fd,1025)
            finally:os.close(fd)
            if freeze.strip()!=b'0' or len(events)>1024 or b'frozen 0' not in events.splitlines():raise Denied('generation unavailable')
        except Denied:raise
        except Exception:raise Denied('generation unavailable') from None
    def verify(self):
        self.check_stop();inspect_bifrost(self.binding)
        pid=inspect_writer(self.writer_binding)
        if self.writer_pid is not None and pid!=self.writer_pid:raise Denied('writer unavailable')
        verify_process_protection(pid)
        self.writer_pid=pid;self.check_stop()
        return {'schema':1,'open':True,'generation':self.g,'grant_sha256':self.scope['grant_sha256'],
                'catalog_sha256':self.scope['catalog_sha256'], 'provider_binding_sha256':self.scope['provider_binding_sha256'],
                'network_device':self.binding['network_device'],'network_inode':self.binding['network_inode']}


def receive(conn,broker):
    conn.settimeout(30)
    _,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    if uid!=2000:raise Denied('peer unavailable')
    data=bytearray()
    while b'\n' not in data and len(data)<=16384:
        chunk=conn.recv(min(4096,16385-len(data)))
        if not chunk:raise Denied('request unavailable')
        data.extend(chunk)
    if len(data)>16384 or not data.endswith(b'\n') or data.count(b'\n')!=1:raise Denied('request unavailable')
    request=json.loads(data[:-1],object_pairs_hook=no_duplicates)
    if not isinstance(request,dict):raise Denied('request unavailable')
    if request=={'op':'guard'}:result=broker.guard()
    elif set(request)=={'op','files'} and request['op']=='write_files':result=broker.write_files({'files':request['files']})
    else:raise Denied('request unavailable')
    reply=json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n'
    if len(reply)>2048:raise Denied('reply unavailable')
    conn.sendall(reply)


def serve_listener(fd,broker):
    listener=socket.fromfd(fd,socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        while True:
            conn,_=listener.accept()
            with conn:
                try:receive(conn,broker)
                except Exception:
                    try:conn.sendall(b'{"error":"unavailable"}\n')
                    except OSError:pass
    finally:listener.close()


def root_file(path,limit=65536):
    for parent in pathlib.Path(path).parents:
        fd=safe_dir(str(parent));os.close(fd)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:return _root_bytes(fd,limit)
    finally:os.close(fd)


def verify_writer_provenance(binding):
    receipt=json.loads(root_file(ETC+'/worker-images.json'),object_pairs_hook=no_duplicates)
    if (set(receipt)!={'schema','purpose','base_image_id','goose_sha256','worker','writer','engine_started'}
            or receipt['schema']!=1 or receipt['purpose']!='nuc-goose-write-files-images-v1'
            or receipt['base_image_id']!='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'):
        raise Denied('writer image provenance unavailable')
    writer=receipt['writer']
    if (set(writer)!={'image_id','program_sha256','files_sha256'}
            or writer['image_id']!='sha256:'+binding['writer_image_sha256']
            or writer['program_sha256']!=binding['writer_program_sha256']
            or set(writer['files_sha256'])!={'nuc_fixed_writer.py','nuc_relay_authority.py'}
            or writer['files_sha256']['nuc_fixed_writer.py']!=binding['writer_program_sha256']):
        raise Denied('writer image provenance unavailable')


def verify_process_protection(pid):
    with open('/proc/'+str(pid)+'/status','rt',encoding='ascii') as f:raw=f.read(65537)
    if len(raw)>65536:raise Denied('writer process unavailable')
    fields=dict(line.split(':',1) for line in raw.splitlines() if ':' in line)
    if (fields.get('Uid','').split()!=['2001']*4 or fields.get('Gid','').split()!=['2001']*4
            or fields.get('NoNewPrivs','').strip()!='1' or fields.get('Seccomp','').strip()!='2'
            or any(int(fields[name].strip(),16)!=0 for name in ('CapEff','CapPrm','CapBnd','CapAmb'))):
        raise Denied('writer process protection unavailable')


def validate_writer_listener(fd,generation):
    listener=socket.fromfd(fd,socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        expected='/run/software-factory-goose/writer/'+generation+'.sock'
        if listener.getsockname()!=expected or listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)!=1:
            raise Denied('listener unavailable')
        parent=safe_dir('/run/software-factory-goose/writer',0,2000,0o710);os.close(parent)
        actual=os.stat(expected,follow_symlinks=False)
        if (not stat.S_ISSOCK(actual.st_mode) or actual.st_uid!=0 or actual.st_gid!=2000
                or stat.S_IMODE(actual.st_mode)!=0o660 or actual.st_nlink!=1):
            raise Denied('listener unavailable')
        try:os.getxattr(expected,'system.posix_acl_access',follow_symlinks=False)
        except OSError as error:
            if error.errno!=__import__('errno').ENODATA:raise Denied('listener ACL unavailable') from None
        else:raise Denied('listener ACL forbidden')
    finally:listener.close()


STARTUP_STAGE='identity'
def main():
    global STARTUP_STAGE
    if os.getuid()!=0 or os.geteuid()!=0 or len(sys.argv)!=2:raise Denied('root launcher binding unavailable')
    generation=sys.argv[1]
    if not re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',generation):raise Denied('generation unavailable')
    if (os.environ.get('LISTEN_PID')!=str(os.getpid()) or os.environ.get('LISTEN_FDS')!='1'
            or os.environ.get('LISTEN_FDNAMES')!='writer'):raise Denied('socket unavailable')
    prefix=ETC+'/relay-catalog/'+generation
    paths={'scope':prefix+'.scope.json','provider':prefix+'.provider.json',
           'catalog':ETC+'/launch-catalog/'+generation+'.json','consumed':ROOT+'/'+generation+'.launch-consumed'}
    opened=[]
    try:
        STARTUP_STAGE='parent_directories'
        for path in paths.values():
            for parent in pathlib.Path(path).parents:
                fd=safe_dir(str(parent));os.close(fd)
        fds={}
        for name,path in paths.items():
            fds[name]=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);opened.append(fds[name])
        STARTUP_STAGE='scope_binding'
        scope,binding=load_root_scope(fds['scope'],fds['consumed'],fds['catalog'],fds['provider'])
        if scope['generation']!=generation:raise Denied('generation unavailable')
        STARTUP_STAGE='task'
        task=json.loads(root_file(ETC+'/tasks/'+generation+'.json'),object_pairs_hook=no_duplicates)
        if (set(task)!={'schema','target_id','task_id','generation','boot_id','cgroup_dev','cgroup_ino'}
                or task['schema']!=1 or task['target_id']!=generation or task['generation']!=generation or task['task_id']!=scope['task_id']):raise Denied('stop catalog unavailable')
        STARTUP_STAGE='handoff_directories'
        for parent in (HANDOFF,HANDOFF+'/'+generation):
            fd=safe_dir(parent,mode=0o700);os.close(fd)
        dirfds={}
        for name,owner in (('input',0),('output',2001),('candidate',2001)):
            fd=safe_dir(HANDOFF+'/'+generation+'/'+name,owner,owner,0o755);opened.append(fd);dirfds[name+'_dir']=fd
        STARTUP_STAGE='writer_binding'
        wfd=os.open(prefix+'.writer.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);opened.append(wfd)
        writer_binding=load_writer_binding(wfd,scope,task,dirfds)
        STARTUP_STAGE='writer_provenance';verify_writer_provenance(writer_binding)
        STARTUP_STAGE='state_directory';state_fd=safe_dir(ROOT,mode=0o700);opened.append(state_fd)
        STARTUP_STAGE='cgroup_directory';cgroup_fd=cgroup2_dir(generation,task);opened.append(cgroup_fd)
        STARTUP_STAGE='listener';validate_writer_listener(3,generation)
        authority=HostAuthority(generation,scope,binding,writer_binding,task,state_fd,cgroup_fd)
        STARTUP_STAGE='authority';authority.verify();STARTUP_STAGE='serving';serve_listener(3,WriterBroker(generation,authority,state_fd,dirfds['input_dir'],dirfds['output_dir']))
    finally:
        for fd in opened:os.close(fd)


if __name__=='__main__':
    try:main()
    except Exception:
        print('writer broker unavailable stage='+STARTUP_STAGE,file=sys.stderr);raise SystemExit(1)
