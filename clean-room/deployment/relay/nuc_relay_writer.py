"""Fixed root writer broker client; the broker itself is not yet installed."""
import json
import os
import re
import socket
import stat
import struct
from nuc_relay_authority import Denied, _no_acl_pinned_dir, _open_path_dir, validate_writer_arguments
from nuc_relay_stream import no_duplicates

class RootWriter:
    def __init__(self, scope):
        generation = scope.get('generation')
        if not isinstance(generation, str) or not re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{26}', generation):
            raise Denied('writer unavailable')
        self.path = '/run/software-factory-goose/writer/' + generation + '.sock'
        self.name = generation + '.sock'

    def _verify_path(self):
        fd = None
        try:
            fd = _open_path_dir('/')
            for part in ('run', 'software-factory-goose', 'writer'):
                child = _open_path_dir(part, dir_fd=fd)
                os.close(fd); fd = child
                st = os.fstat(fd)
                if st.st_uid != 0 or st.st_mode & 0o022:
                    raise Denied('writer unavailable')
                _no_acl_pinned_dir(fd)
            st = os.stat(self.name, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISSOCK(st.st_mode) or st.st_uid != 0 or st.st_gid != 2000
                    or stat.S_IMODE(st.st_mode) != 0o660 or st.st_nlink != 1):
                raise Denied('writer unavailable')
        except OSError:
            raise Denied('writer unavailable') from None
        finally:
            if fd is not None:os.close(fd)

    def execute(self, arguments):
        try:
            raw = json.dumps(arguments, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
            validate_writer_arguments(raw)
            frame = json.dumps({'op':'write_files', 'files':arguments['files']}, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
            self._verify_path()
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                conn.settimeout(30)
                conn.connect(self.path)
                _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != 0:
                    raise Denied('writer unavailable')
                conn.sendall(frame + b'\n')
                reply = bytearray()
                while b'\n' not in reply and len(reply) <= 65536:
                    chunk = conn.recv(min(4096, 65537-len(reply)))
                    if not chunk:raise Denied('writer outcome unknown')
                    reply.extend(chunk)
                if not reply.endswith(b'\n') or len(reply) > 65536 or reply.count(b'\n') != 1:
                    raise Denied('writer outcome unknown')
                result = json.loads(reply[:-1], object_pairs_hook=no_duplicates,
                                    parse_constant=lambda _: (_ for _ in ()).throw(Denied('writer outcome unknown')))
                return result
            finally:
                conn.close()
        except Denied:
            raise
        except Exception:
            raise Denied('writer outcome unknown') from None
