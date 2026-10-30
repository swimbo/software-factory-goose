"""Per-generation callback transport and named systemd-FD validation.

No executable entry point: root grant, stop authority, provider connector and
writer broker must be integrated before a production service can be started.
"""
import fcntl
import json
import os
import re
import socket
import stat
from nuc_relay_authority import Denied, _no_acl, _no_acl_pinned_dir, _open_path_dir, require_worker_peer
from nuc_relay_stream import no_duplicates

REQUEST_LIMIT = 65536
REPLY_LIMIT = 12 * 1024 * 1024
EXPECTED_NAMES = frozenset(('scope', 'catalog', 'consumed', 'provider', 'provider-binding', 'callback'))


def named_descriptors(env, pid):
    try:
        if str(pid) != env['LISTEN_PID']:
            raise Denied('descriptor unavailable')
        count = int(env['LISTEN_FDS'])
        names = env['LISTEN_FDNAMES'].split(':')
        if count != len(EXPECTED_NAMES) or len(names) != count or set(names) != EXPECTED_NAMES:
            raise Denied('descriptor unavailable')
        return {name: 3 + i for i, name in enumerate(names)}
    except (KeyError, TypeError, ValueError):
        raise Denied('descriptor unavailable') from None


def validate_provider_descriptor(fd):
    """Check metadata only; no secret is read by this function."""
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 1000
                or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1
                or not 0 < st.st_size <= 4096
                or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY):
            raise Denied('provider descriptor unavailable')
        _no_acl(fd, False)
    except OSError:
        raise Denied('provider descriptor unavailable') from None


def validate_listener(fd, generation):
    if not isinstance(generation, str) or not re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{26}', generation):
        raise Denied('listener unavailable')
    path = '/run/software-factory-goose/relay/' + generation + '/relay.sock'
    directory_fd = None
    try:
        directory_fd = _open_path_dir('/')
        for name in ('run', 'software-factory-goose', 'relay', generation):
            child = _open_path_dir(name, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child
            entry = os.fstat(directory_fd)
            if name != generation:
                if entry.st_uid != 0 or entry.st_mode & 0o022:
                    raise Denied('listener unavailable')
            _no_acl_pinned_dir(directory_fd)
        directory = os.fstat(directory_fd)
        entry = os.stat('relay.sock', dir_fd=directory_fd, follow_symlinks=False)
        sock = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                    or directory.st_gid != 2000 or stat.S_IMODE(directory.st_mode) != 0o710
                    or not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != 0 or entry.st_gid != 2001
                    or stat.S_IMODE(entry.st_mode) != 0o660
                    or sock.getsockname() != path
                    or sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1):
                raise Denied('listener unavailable')
        finally:
            sock.close()
    except (OSError, ValueError):
        raise Denied('listener unavailable') from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def serve_connection(conn, core):
    """One bounded, authenticated frame; no provider or writer selected by the frame."""
    conn.settimeout(30)
    require_worker_peer(conn)
    raw = bytearray()
    while b'\n' not in raw and len(raw) <= REQUEST_LIMIT:
        chunk = conn.recv(min(4096, REQUEST_LIMIT + 1 - len(raw)))
        if not chunk:
            raise Denied('frame unavailable')
        raw.extend(chunk)
    if not raw.endswith(b'\n') or len(raw) > REQUEST_LIMIT or raw.count(b'\n') != 1:
        raise Denied('frame unavailable')
    try:
        value = json.loads(raw[:-1], object_pairs_hook=no_duplicates,
                           parse_constant=lambda _: (_ for _ in ()).throw(Denied('invalid frame')))
        result = core.call(conn, value)
        out = json.dumps({'ok': True, 'value': result}, separators=(',', ':'), ensure_ascii=False).encode()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Denied('frame unavailable') from None
    if len(out) > REPLY_LIMIT:
        raise Denied('reply unavailable')
    conn.sendall(out)
