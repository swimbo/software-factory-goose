#!/usr/bin/env python3
"""Fixture-only durable two-root ownership. Not a production containment authority."""
import fcntl
import json
import os
import pathlib
import selectors
import subprocess
import time
import stat
import uuid
from contextlib import contextmanager

from docker_owner_guardian import DisposableContainer, LABEL, docker

ROLES = frozenset(('goose', 'executor'))
APPROVED_SLICE = 'sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0-worker.slice'
CGROUP_PATH = pathlib.Path('/sys/fs/cgroup/sfactory6a2ae9a8ef374a84b94c15a1b1d4d7f0.slice') / APPROVED_SLICE

def _bounded_exec(command, payload, cancelled, timeout=10, cap=65536):
    """Own and reap only the Docker CLI child; timeout never proves exec termination."""
    if not isinstance(payload, bytes) or len(payload)>65536: raise RuntimeError('input bound exceeded')
    child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    selector=selectors.DefaultSelector(); output=bytearray(); sent=0; deadline=time.monotonic()+timeout
    try:
        os.set_blocking(child.stdin.fileno(),False); os.set_blocking(child.stdout.fileno(),False)
        selector.register(child.stdout,selectors.EVENT_READ)
        if payload: selector.register(child.stdin,selectors.EVENT_WRITE)
        else: child.stdin.close()
        while selector.get_map():
            if cancelled(): raise RuntimeError('stop requested during exec')
            if time.monotonic()>=deadline: raise RuntimeError('exec deadline exceeded')
            for key,_ in selector.select(min(.05,max(0,deadline-time.monotonic()))):
                if key.fileobj is child.stdin:
                    try: n=os.write(child.stdin.fileno(),payload[sent:sent+8192])
                    except BrokenPipeError: raise RuntimeError('executor input closed')
                    except BlockingIOError: continue
                    sent+=n
                    if sent==len(payload): selector.unregister(child.stdin); child.stdin.close()
                else:
                    try: chunk=os.read(child.stdout.fileno(),8192)
                    except BlockingIOError: continue
                    if not chunk: selector.unregister(child.stdout); child.stdout.close(); continue
                    output.extend(chunk)
                    if len(output)>cap: raise RuntimeError('executor output bound exceeded')
        if cancelled(): raise RuntimeError('stop requested during exec')
        remaining=deadline-time.monotonic()
        if remaining<=0: raise RuntimeError('exec deadline exceeded')
        if child.wait(timeout=remaining)!=0: raise RuntimeError('executor failed')
        return bytes(output)
    finally:
        selector.close()
        for stream in (child.stdin,child.stdout):
            if stream is not None and not stream.closed: stream.close()
        if child.poll() is None:
            child.kill(); child.wait(timeout=2)

class Batch:
    """Trusted local caller only; never expose create arguments to an untrusted peer."""
    def __init__(self, root, slice_name, cgroup, candidate=None, candidate_readonly=False):
        self.root = pathlib.Path(root)
        if slice_name != APPROVED_SLICE or pathlib.Path(cgroup) != CGROUP_PATH:
            raise RuntimeError('unapproved slice observation path')
        # Reject aliasing and symlink replacement of the fixed trusted path.
        if CGROUP_PATH.resolve(strict=True) != CGROUP_PATH:
            raise RuntimeError('noncanonical slice path')
        self.slice = slice_name
        self.cgroup = CGROUP_PATH
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
                raise RuntimeError('batch root must be private and owned')
        finally:
            os.close(fd)
        self.inode = self.cgroup.stat().st_ino
        if not isinstance(candidate_readonly, bool) or (candidate is None and candidate_readonly):
            raise RuntimeError('invalid candidate mode')
        self.candidate = None
        if candidate is not None:
            path = pathlib.Path(candidate)
            if path.resolve(strict=True) != path or path.is_symlink() or not path.is_dir():
                raise RuntimeError('candidate path must be canonical')
            parent = path.parent.stat(); st = path.stat()
            if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700 or st.st_uid != os.geteuid():
                raise RuntimeError('candidate requires owned private parent')
            self.candidate = {'path':str(path), 'dev':st.st_dev, 'inode':st.st_ino, 'readonly':candidate_readonly}
            self.check_candidate()

    def check_candidate(self):
        if self.candidate is None: return
        path = pathlib.Path(self.candidate['path'])
        if path.resolve(strict=True) != path or path.is_symlink(): raise RuntimeError('candidate path changed')
        st=path.stat(); parent=path.parent.stat()
        if (st.st_dev,st.st_ino)!=(self.candidate['dev'],self.candidate['inode']) or st.st_uid!=os.geteuid() or parent.st_uid!=os.geteuid() or stat.S_IMODE(parent.st_mode)!=0o700:
            raise RuntimeError('candidate identity or privacy changed')
        count=0
        for directory, dirs, files in os.walk(path,followlinks=False):
            for name in dirs+files:
                count+=1
                if count>10000 or name=='.git': raise RuntimeError('candidate tree rejected')
                item=pathlib.Path(directory)/name
                entry=item.lstat()
                if stat.S_ISLNK(entry.st_mode) or entry.st_dev!=st.st_dev or not (stat.S_ISDIR(entry.st_mode) or stat.S_ISREG(entry.st_mode)) or (stat.S_ISREG(entry.st_mode) and entry.st_nlink!=1): raise RuntimeError('candidate entry rejected')
        final=path.stat()
        if (final.st_dev,final.st_ino)!=(st.st_dev,st.st_ino): raise RuntimeError('candidate changed during inspection')

    @contextmanager
    def locked(self):
        fd = os.open(self.root/'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def commit(self, name, value):
        tmp = self.root/(name+'.'+uuid.uuid4().hex+'.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(value, f, sort_keys=True); f.flush(); os.fsync(f.fileno())
            os.replace(tmp, self.root/name)
            fd2 = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: os.fsync(fd2)
            finally: os.close(fd2)
        finally:
            if tmp.exists(): tmp.unlink()

    def read(self, name):
        fd = os.open(self.root/name, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            st = os.fstat(f.fileno())
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600 or not stat.S_ISREG(st.st_mode):
                raise RuntimeError('unsafe batch record')
            return json.load(f)

    def verify_slice(self):
        if self.cgroup.stat().st_ino != self.inode: raise RuntimeError('slice identity changed')

    def prepare_fixed(self, role, image, command, options=()):
        if role not in ROLES or not image.startswith('sha256:') or len(image) != 71 or any(c not in '0123456789abcdef' for c in image[7:]) or not command:
            raise RuntimeError('invalid fixed spec')
        options = list(options)
        for i in range(0, len(options), 2):
            if i+1 >= len(options) or options[i] not in ('--mount','--tmpfs','--workdir','--env','--entrypoint'):
                raise RuntimeError('unsupported fixed spec option')
            if options[i] == '--mount' and ('readonly' not in options[i+1].split(',') or 'type=bind' not in options[i+1].split(',')):
                raise RuntimeError('only read-only bind mounts permitted')
            if role=='executor' and self.candidate is not None and ((options[i]=='--mount' and any(x in ('dst=/work','destination=/work','target=/work') for x in options[i+1].split(','))) or (options[i]=='--tmpfs' and options[i+1].split(':',1)[0]=='/work')):
                raise RuntimeError('candidate mount target is reserved')
        with self.locked():
            self.verify_slice()
            if (self.root/'closed.json').exists() or (self.root/'sealed.json').exists() or (self.root/(role+'.intent')).exists():
                raise RuntimeError('admission closed or role already reserved')
            token = uuid.uuid4().hex
            intent = {'role':role,'token':token,'slice':self.slice,'inode':self.inode}
            if role=='executor' and self.candidate is not None:
                self.check_candidate(); intent['candidate']=dict(self.candidate)
                options += ['--mount','type=bind,src='+self.candidate['path']+',dst=/work'+(',readonly' if self.candidate['readonly'] else '')]
            self.commit(role+'.intent', intent)
            owner = DisposableContainer(token)
            result = docker('create','--name',owner.name,'--label',LABEL+'='+token,'--cgroup-parent',self.slice,
                '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                '--pids-limit','24','--memory','128m','--cpus','0.5','--user','1001:1001','--pull','never',
                '--log-driver','json-file','--log-opt','max-size=1m','--log-opt','max-file=2',
                *options,image,*command)
            ident = result.stdout.strip()
            if len(ident)!=64 or any(c not in '0123456789abcdef' for c in ident): raise RuntimeError('invalid engine ID')
            owner.ident = ident; obj = owner.inspect(ident)
            if obj is None or obj['State']['Running'] or obj['State']['Status'] != 'created' or obj['HostConfig']['CgroupParent'] != self.slice:
                raise RuntimeError('created root unverified')
            self.commit(role+'.manifest',dict(intent,id=ident))
            if (self.root/'closed.json').exists(): raise RuntimeError('admission closed during create; root quarantined')
            return token

    def seal(self):
        with self.locked():
            self.verify_slice()
            if (self.root/'closed.json').exists() or (self.root/'sealed.json').exists(): raise RuntimeError('batch unavailable')
            ids=set()
            for role in ROLES:
                intent=self.read(role+'.intent'); manifest=self.read(role+'.manifest')
                if any(manifest.get(k)!=intent[k] for k in ('role','token','slice','inode')) or manifest.get('candidate')!=intent.get('candidate') or intent['role']!=role or intent['slice']!=self.slice or intent['inode']!=self.inode:
                    raise RuntimeError('catalogue unverified')
                if intent.get('candidate') is not None:
                    if self.candidate!=intent['candidate']: raise RuntimeError('candidate binding unavailable')
                    self.check_candidate()
                owner=DisposableContainer(intent['token']); owner.ident=manifest['id']; obj=owner.inspect(owner.ident)
                if obj is None or obj['State']['Running'] or obj['State']['Status']!='created' or obj['HostConfig']['CgroupParent']!=self.slice or owner.ident in ids:
                    raise RuntimeError('catalogue target unavailable')
                ids.add(owner.ident)
            self.commit('sealed.json', {'slice':self.slice,'inode':self.inode})

    def start(self, role):
        with self.locked():
            self.verify_slice()
            if role not in ROLES or (self.root/'closed.json').exists() or not (self.root/'sealed.json').exists() or (self.root/(role+'.started')).exists():
                raise RuntimeError('launch denied')
            record=self.read(role+'.manifest'); intent=self.read(role+'.intent'); seal=self.read('sealed.json')
            if any(record.get(k)!=intent[k] for k in ('role','token','slice','inode')) or record.get('candidate')!=intent.get('candidate') or seal != {'slice':self.slice,'inode':self.inode}: raise RuntimeError('catalogue identity changed')
            if intent.get('candidate') is not None:
                if self.candidate!=intent['candidate']: raise RuntimeError('candidate binding unavailable')
                self.check_candidate()
            if record['role']!=role or record['slice']!=self.slice or record['inode']!=self.inode: raise RuntimeError('manifest mismatch')
            owner=DisposableContainer(record['token']); owner.ident=record['id']; obj=owner.inspect(owner.ident)
            if obj is None or obj['State']['Status']!='created' or obj['HostConfig']['CgroupParent']!=self.slice: raise RuntimeError('launch identity changed')
            # Write before starting: ambiguous Docker outcomes can never be retried as a fresh start.
            self.commit(role+'.started',{'id':owner.ident})
            docker('start',owner.ident)
            if (self.root/'closed.json').exists():
                # A stop requested during Docker start cannot be reported as a
                # launch. Stop this owned root before releasing the family lock.
                owner.cleanup()
                self.commit(role+'.receipt',{'token':intent['token']})
                raise RuntimeError('launch raced stop and was quarantined')
            return owner.ident

    def exec_once(self, payload):
        """Trusted host supplies bounded input; Docker argv and target are fixed."""
        if not isinstance(payload,bytes) or len(payload)>65536: raise RuntimeError('input bound exceeded')
        with self.locked():
            self.verify_slice()
            if (self.root/'closed.json').exists() or not (self.root/'sealed.json').exists() or (self.root/'executor.exec').exists(): raise RuntimeError('executor unavailable')
            intent=self.read('executor.intent'); record=self.read('executor.manifest')
            if any(record.get(k)!=intent[k] for k in ('role','token','slice','inode')) or record.get('candidate')!=intent.get('candidate') or record['role']!='executor': raise RuntimeError('executor binding mismatch')
            if not (self.root/'executor.started').is_file() or self.read('sealed.json') != {'slice':self.slice,'inode':self.inode} or self.read('executor.started') != {'id':record['id']}: raise RuntimeError('executor start not owned')
            if intent.get('candidate') is not None:
                if self.candidate!=intent['candidate']: raise RuntimeError('candidate binding unavailable')
                self.check_candidate()
            owner=DisposableContainer(record['token']); owner.ident=record['id']; obj=owner.inspect(owner.ident)
            if obj is None or not obj['State']['Running'] or obj['HostConfig']['CgroupParent']!=self.slice: raise RuntimeError('executor not running')
            self.commit('executor.exec',{'id':owner.ident})
            try:
                result=_bounded_exec(['docker','exec','-i',owner.ident,'/execution','--tool-request'],payload,lambda:(self.root/'closed.json').exists())
                if (self.root/'closed.json').exists(): raise RuntimeError('stop requested before output release')
                return result
            except Exception:
                if not (self.root/'closed.json').exists(): self.commit('closed.json',{'slice':self.slice,'inode':self.inode})
                raise

    def stop(self):
        # Admission closure is durable even if a create/start currently holds the
        # lock. An in-flight operation remains unresolved until a later stop.
        if not (self.root/'closed.json').exists(): self.commit('closed.json',{'slice':self.slice,'inode':self.inode})
        with self.locked():
            self.verify_slice()
            if self.read('closed.json') != {'slice':self.slice,'inode':self.inode}: raise RuntimeError('closure identity mismatch')
            if not any((self.root/(role+'.intent')).exists() for role in ROLES): raise RuntimeError('no owned roots')
            for role in ROLES:
                if not (self.root/(role+'.intent')).exists(): continue
                intent=self.read(role+'.intent')
                if intent['role']!=role or intent['slice']!=self.slice or intent['inode']!=self.inode: raise RuntimeError('intent mismatch')
                owner=DisposableContainer(intent['token'])
                if (self.root/(role+'.receipt')).exists():
                    if self.read(role+'.receipt') != {'token':intent['token']}: raise RuntimeError('receipt mismatch')
                    continue
                manifest_path=self.root/(role+'.manifest')
                if manifest_path.exists():
                    manifest=self.read(role+'.manifest')
                    if any(manifest.get(k)!=intent[k] for k in ('role','token','slice','inode')) or manifest.get('candidate')!=intent.get('candidate'): raise RuntimeError('manifest mismatch')
                    owner.ident=manifest['id']; obj=owner.inspect(owner.ident)
                    if obj is None or obj['HostConfig']['CgroupParent']!=self.slice: raise RuntimeError('owned target unavailable')
                    owner.cleanup()
                else:
                    obj=owner.inspect(owner.name)
                    if obj is None or obj['Name']!='/'+owner.name or obj['State']['Running'] or obj['State']['Status']!='created' or obj['HostConfig']['CgroupParent']!=self.slice:
                        raise RuntimeError('uncommitted target unresolved')
                    ident=obj['Id']; matches=docker('ps','-a','--filter','label='+LABEL+'='+intent['token'],'--no-trunc','--format','{{.ID}}').stdout.split()
                    if len(ident)!=64 or matches!=[ident]: raise RuntimeError('uncommitted identity ambiguous')
                    owner.ident=ident; docker('rm',ident)
                    if owner.inspect(ident) is not None: raise RuntimeError('uncommitted removal unresolved')
                self.commit(role+'.receipt',{'token':intent['token']})
            self.verify_slice()
            if 'populated 0' not in (self.cgroup/'cgroup.events').read_text(): raise RuntimeError('subtree empty unverified')
            return True
