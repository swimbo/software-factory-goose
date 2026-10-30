"""Root broker candidate: fixed typed writer handoff, never Docker exec.

This module has no executable entry point until the root launch catalog, kernel
closure guard, and per-generation systemd socket are bound and reviewed.
"""
import hashlib
import json
import os
import re
import stat
import threading
import time
from nuc_relay_authority import Denied, _no_acl, validate_writer_arguments
from nuc_relay_stream import no_duplicates

NAMES=('hello.py','test_hello.py')


def _durable_create(dirfd,name,data,mode):
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=dirfd)
    try:
        os.fchmod(fd,mode)
        view=memoryview(data)
        while view:
            count=os.write(fd,view)
            if count<=0:raise Denied('publication unavailable')
            view=view[count:]
        os.fsync(fd)
    finally:os.close(fd)
    os.fsync(dirfd)


def _publish(dirfd,name,data):
    # Fixed per-generation names. Existing or partial temporary files permanently deny.
    temporary='.'+name+'.pending'
    _durable_create(dirfd,temporary,data,0o444)
    os.link(temporary,name,src_dir_fd=dirfd,dst_dir_fd=dirfd,follow_symlinks=False)
    os.fsync(dirfd)
    os.unlink(temporary,dir_fd=dirfd)
    os.fsync(dirfd)


def _read_result(dirfd):
    fd=os.open('result.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=dirfd)
    try:
        st=os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid!=2001 or st.st_gid!=2001
                or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o644 or not 0<st.st_size<=2048):
            raise Denied('writer result unavailable')
        _no_acl(fd,False)
        raw=os.read(fd,2049)
        if len(raw)!=st.st_size:raise Denied('writer result unavailable')
        return json.loads(raw,object_pairs_hook=no_duplicates)
    finally:os.close(fd)


class WriterBroker:
    def __init__(self,generation,authority,state_fd,input_fd,output_fd):
        if not isinstance(generation,str) or not re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{26}',generation):
            raise Denied('generation unavailable')
        self.generation=generation;self.authority=authority
        self.state_fd=state_fd;self.input_fd=input_fd;self.output_fd=output_fd
        self.lock=threading.Lock()

    def guard(self):
        # Authority must independently verify closed record, boot, cgroup inode/freeze,
        # complete grant/catalog and Bifrost identity. An absent implementation denies.
        value=self.authority.verify()
        if not isinstance(value,dict) or value.get('open') is not True:raise Denied('guard unavailable')
        return value

    def write_files(self,value):
        with self.lock:
            try:
                raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
                request=validate_writer_arguments(raw)
                expected={name:hashlib.sha256(request['files'][name].encode('utf-8')).hexdigest() for name in NAMES}
                digest=hashlib.sha256(raw).hexdigest()
                self.guard()
                _durable_create(self.state_fd,self.generation+'.writer-intent', (self.generation+'\n'+digest+'\n').encode(),0o600)
                self.guard()
                _publish(self.input_fd,'request.json',raw)
                self.guard()
                _publish(self.input_fd,'ready',(digest+'\n').encode())
                self.guard()
                deadline=time.monotonic()+180
                while True:
                    self.authority.check_stop()
                    try:result=_read_result(self.output_fd);break
                    except FileNotFoundError:
                        if time.monotonic()>=deadline:raise Denied('writer outcome unknown')
                        time.sleep(.25)
                self.guard()
                if (not isinstance(result,dict) or set(result)!={'status','digests'}
                        or result['status']!='executed' or result['digests']!=expected):
                    raise Denied('writer outcome unknown')
                return {'status':'executed','exit_code':0,'stdout':'Both task files written.','stderr':''}
            except Denied:raise
            except Exception:raise Denied('writer outcome unknown') from None
