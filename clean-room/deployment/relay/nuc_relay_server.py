#!/usr/bin/python3
"""Systemd-activated relay candidate. Root guard and writer broker are required."""
import os
import ctypes
import json
import hashlib
import errno
import socket
import sys

# Production installs the whole directory root-owned and non-writable. Python -I
# does not add the script directory, so add precisely this reviewed directory.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from nuc_relay_authority import Denied, EffectFence, _no_acl, load_root_scope
from nuc_relay_core import RelayCore
from nuc_relay_guard import RootGuard
from nuc_relay_provider import LoopbackProvider
from nuc_relay_systemd import named_descriptors, serve_connection, validate_listener, validate_provider_descriptor
from nuc_relay_writer import RootWriter


def fence_directory(generation):
    fd=None
    try:
        fd=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW)
        for part in ('var','lib','software-factory-goose','relay',generation):
            child=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
            st=os.fstat(fd)
            if part != generation and (st.st_uid!=0 or st.st_mode&0o022):raise Denied('fence unavailable')
            for attribute in ('system.posix_acl_access','system.posix_acl_default'):
                try:os.getxattr('/proc/self/fd/'+str(fd),attribute)
                except OSError as exc:
                    if exc.errno==errno.ENODATA:continue
                    raise Denied('directory ACL unavailable') from None
                raise Denied('directory ACL forbidden')
        usable=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        os.close(fd);fd=usable
        return fd
    except Exception:
        if fd is not None:os.close(fd)
        raise Denied('fence unavailable') from None


def in_generation_slice(generation):
    try:
        with open('/proc/self/cgroup','rt',encoding='ascii') as file:
            raw=file.read(4097)
        lines=raw.splitlines()
        if len(raw)>4096 or len(lines)!=1 or not lines[0].startswith('0::/'):
            raise Denied('slice unavailable')
        components=lines[0][4:].split('/')
        if 'sfactory'+generation.lower()+'.slice' not in components:
            raise Denied('slice unavailable')
    except (OSError,UnicodeError):raise Denied('slice unavailable') from None


def protect_memory():
    try:
        if ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)!=0:raise Denied('memory protection unavailable')
    except (AttributeError,OSError):raise Denied('memory protection unavailable') from None


def main():
    if (os.getuid()!=2000 or os.geteuid()!=2000 or os.getgid()!=2000 or os.getegid()!=2000
            or any(group != 2000 for group in os.getgroups()) or len(sys.argv)!=1):
        raise Denied('service unavailable')
    # Prevent same-role processes reading provider memory/fds through proc or core.
    protect_memory()
    descriptors=named_descriptors(os.environ,os.getpid())
    scope,binding=load_root_scope(descriptors['scope'],descriptors['consumed'],descriptors['catalog'],descriptors['provider-binding'])
    generation=scope['generation']
    in_generation_slice(generation)
    validate_listener(descriptors['callback'],generation)
    validate_provider_descriptor(descriptors['provider'])
    guard=RootGuard(scope,binding)
    # Missing or unreviewed root guard is a hard startup failure, before serving.
    guard.check(scope)
    directory=fence_directory(generation)
    try:fence=EffectFence(directory)
    finally:os.close(directory)
    provider=LoopbackProvider(binding,descriptors['provider'])
    writer=RootWriter(scope)
    core=RelayCore(descriptors['scope'],descriptors['consumed'],descriptors['catalog'],descriptors['provider-binding'],
                   fence,guard.check,provider.send,writer.execute)
    listener=socket.fromfd(descriptors['callback'],socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        while True:
            conn,_=listener.accept()
            with conn:
                try:
                    serve_connection(conn,core)
                    if core.phase=='done':
                        # Write once after the final bounded reply was sent. A send/fsync
                        # ambiguity retains effect markers and never reopens admission.
                        raw=json.dumps({'schema':1,'generation':generation,'binding_sha256':scope['grant_sha256'],'observations':core.observations,'phase':'done'},sort_keys=True,separators=(',',':')).encode()+b'\n'
                        fd=os.open(generation+'.done.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fence.dirfd)
                        try:
                            if os.write(fd,raw)!=len(raw):raise Denied('completion receipt unavailable')
                            os.fsync(fd)
                        finally:os.close(fd)
                        os.fsync(fence.dirfd)
                except Exception:
                    try:conn.sendall(b'{"ok":false,"value":null}')
                    except OSError:pass
    finally:
        listener.close();os.close(fence.dirfd);os.close(provider.credential_fd)

if __name__=='__main__':
    try:main()
    except Exception:
        # Do not print upstream errors, request content or credential material.
        print('relay unavailable',file=sys.stderr)
        raise SystemExit(1)
