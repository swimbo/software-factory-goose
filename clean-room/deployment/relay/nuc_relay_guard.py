"""Proposed root guard protocol; the corresponding root service is not installed."""
import json
import os
import re
import socket
import stat
import struct
from nuc_relay_authority import Denied, _no_acl_pinned_dir, _open_path_dir
from nuc_relay_stream import no_duplicates

class RootGuard:
    def __init__(self, scope, binding):
        generation=scope.get('generation')
        if not isinstance(generation,str) or not re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{26}',generation):
            raise Denied('guard unavailable')
        self.generation=generation
        self.name=generation+'.sock'
        self.path='/run/software-factory-goose/writer/'+self.name
        self.expected={'schema':1,'open':True,'generation':generation,
                       'grant_sha256':scope['grant_sha256'], 'catalog_sha256':scope['catalog_sha256'],
                       'provider_binding_sha256':scope['provider_binding_sha256'],
                       'network_device':binding['network_device'],'network_inode':binding['network_inode']}
    def _verify_path(self):
        fd=None
        try:
            fd=_open_path_dir('/')
            for part in ('run','software-factory-goose','writer'):
                child=_open_path_dir(part,dir_fd=fd)
                os.close(fd);fd=child
                st=os.fstat(fd)
                if st.st_uid!=0 or st.st_mode&0o022:raise Denied('guard unavailable')
                _no_acl_pinned_dir(fd)
            st=os.stat(self.name,dir_fd=fd,follow_symlinks=False)
            if (not stat.S_ISSOCK(st.st_mode) or st.st_uid!=0 or st.st_gid!=2000
                    or stat.S_IMODE(st.st_mode)!=0o660 or st.st_nlink!=1):raise Denied('guard unavailable')
        except OSError:raise Denied('guard unavailable') from None
        finally:
            if fd is not None:os.close(fd)
    def check(self, scope):
        if scope.get('generation')!=self.generation:raise Denied('guard unavailable')
        self._verify_path()
        try:
            conn=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                conn.settimeout(5);conn.connect(self.path)
                _,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if uid!=0:raise Denied('guard unavailable')
                conn.sendall(b'{"op":"guard"}\n')
                raw=bytearray()
                while b'\n' not in raw and len(raw)<=1024:
                    chunk=conn.recv(min(1025-len(raw),1025))
                    if not chunk:raise Denied('guard unavailable')
                    raw.extend(chunk)
                if len(raw)>1024 or not raw.endswith(b'\n') or raw.count(b'\n')!=1:raise Denied('guard unavailable')
                reply=json.loads(raw[:-1],object_pairs_hook=no_duplicates)
                if (not isinstance(reply,dict) or type(reply.get('schema')) is not int
                        or reply.get('open') is not True or type(reply.get('network_device')) is not int
                        or type(reply.get('network_inode')) is not int or reply != self.expected):raise Denied('guard unavailable')
                return True
            finally:conn.close()
        except Denied:raise
        except Exception:raise Denied('guard unavailable') from None
