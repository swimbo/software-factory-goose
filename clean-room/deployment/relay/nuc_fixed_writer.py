#!/usr/bin/python3
"""Fixed two-file writer; no shell or model-supplied paths or commands."""
import hashlib
import json
import os
import signal
import stat
import sys
import time
import uuid
sys.path.insert(0,os.path.dirname(os.path.realpath(__file__)))
from nuc_relay_authority import Denied, _no_acl, validate_writer_arguments

NAMES=('hello.py','test_hello.py')

def read_regular(dirfd,name,owner,mode,limit):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=dirfd)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=owner or st.st_gid!=owner or stat.S_IMODE(st.st_mode)!=mode or st.st_nlink!=1 or not 0<st.st_size<=limit:raise Denied('input unavailable')
        _no_acl(fd,False)
        data=os.read(fd,limit+1)
        if len(data)!=st.st_size:raise Denied('input unavailable')
        return data
    finally:os.close(fd)


def exclusive_file(dirfd,name,data,mode):
    temp='.factory-'+uuid.uuid4().hex
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=dirfd)
    try:
        os.fchmod(fd,mode)
        view=memoryview(data)
        while view:
            n=os.write(fd,view)
            if n<=0:raise Denied('write unavailable')
            view=view[n:]
        os.fsync(fd)
    finally:os.close(fd)
    try:
        os.link(temp,name,src_dir_fd=dirfd,dst_dir_fd=dirfd,follow_symlinks=False)
        os.fsync(dirfd)
    finally:
        os.unlink(temp,dir_fd=dirfd)
        os.fsync(dirfd)


def run_once(input_fd,output_fd,candidate_fd):
    ready=read_regular(input_fd,'ready',0,0o444,128)
    request=read_regular(input_fd,'request.json',0,0o444,12288)
    if ready != hashlib.sha256(request).hexdigest().encode()+b'\n':raise Denied('input unavailable')
    value=validate_writer_arguments(request)
    # Each path is fixed and exclusive. Any partial write is an unknown result;
    # this process never reopens admission or overwrites an existing file.
    digests={}
    for name in NAMES:
        data=value['files'][name].encode('utf-8')
        exclusive_file(candidate_fd,name,data,0o644)
        digests[name]=hashlib.sha256(data).hexdigest()
    receipt=json.dumps({'status':'executed','digests':digests},sort_keys=True,separators=(',',':')).encode()
    exclusive_file(output_fd,'result.json',receipt,0o644)


def main():
    if os.getuid()!=2001 or os.geteuid()!=2001 or len(sys.argv)!=1:raise Denied('writer unavailable')
    opened=[]
    try:
        for path in ('/handoff/input','/handoff/output','/candidate'):
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);opened.append(fd)
        for fd,owner,mode in zip(opened,(0,2001,2001),(0o755,0o755,0o755)):
            st=os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=owner or stat.S_IMODE(st.st_mode)!=mode:raise Denied('writer unavailable')
            _no_acl(fd,True)
        deadline=time.monotonic()+180
        while True:
            try:os.stat('ready',dir_fd=opened[0],follow_symlinks=False)
            except FileNotFoundError:
                if time.monotonic()>=deadline:raise Denied('writer unavailable')
                time.sleep(.1)
                continue
            run_once(*opened)
            # Remain in the generation cgroup until independently stopped. The broker can
            # verify the same fixed writer PID and mounts after reading the receipt.
            while True:signal.pause()
    finally:
        for fd in opened:os.close(fd)

if __name__=='__main__':
    try:main()
    except Exception:
        print('writer unavailable',file=sys.stderr)
        raise SystemExit(1)
