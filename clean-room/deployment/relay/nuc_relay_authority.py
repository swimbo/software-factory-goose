"""Unregistered NUC relay authority primitives. No provider or writer is activated.

A root launcher must pass four already-open descriptors: a root-authored scope,
its catalogue, provider binding, and its immutable launch-consumed record. The runtime adapter is deliberately absent
until the launcher/catalog protocol and isolated provider transport are reviewed.
"""
import fcntl
import errno
import datetime
import hashlib
import json
import os
import re
import socket
import stat
import struct
import sys
import time

class Denied(Exception):
    pass

WRITE_TOOL = {'type': 'function', 'function': {'name': 'factory__write_files',
    'description': 'Write the two authorized task files without executing code.',
    'parameters': {'type': 'object', 'properties': {'files': {'type': 'object',
        'properties': {'hello.py': {'type': 'string', 'maxLength': 8192},
                       'test_hello.py': {'type': 'string', 'maxLength': 8192}},
        'required': ['hello.py', 'test_hello.py'], 'additionalProperties': False}},
        'required': ['files'], 'additionalProperties': False}}}

def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied('duplicate field')
        result[key] = value
    return result


def _root_bytes(fd, limit):
    st = os.fstat(fd)
    if not (stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == 0
            and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1
            and 0 < st.st_size <= limit):
        raise Denied('root descriptor unavailable')
    # Reject a writable description: relay must not be able to modify the authority.
    if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        raise Denied('root descriptor unavailable')
    _no_acl(fd, False)
    data = os.pread(fd, limit + 1, 0)
    if len(data) != st.st_size or len(data) > limit:
        raise Denied('root descriptor changed')
    return data


def _no_acl(fd, directory):
    if sys.platform != 'linux':
        return  # Local synthetic tests do not establish Linux ACL behavior.
    names = ('system.posix_acl_access', 'system.posix_acl_default') if directory else ('system.posix_acl_access',)
    for name in names:
        try:
            os.getxattr(fd, name)
        except OSError as error:
            if error.errno == errno.ENODATA:
                continue
            raise Denied('ACL unavailable') from None
        raise Denied('ACL unavailable')


def _open_path_dir(path, *, dir_fd=None):
    flags = (os.O_PATH if sys.platform == 'linux' else os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    return os.open(path, flags, dir_fd=dir_fd)


def _no_acl_pinned_dir(fd):
    if sys.platform != 'linux':
        return
    for name in ('system.posix_acl_access', 'system.posix_acl_default'):
        try:
            os.getxattr('/proc/self/fd/' + str(fd), name)
        except OSError as error:
            if error.errno == errno.ENODATA:
                continue
            raise Denied('ACL unavailable') from None
        raise Denied('ACL unavailable')


def load_root_scope(scope_fd, consumed_fd, catalog_fd, binding_fd):
    try:
        raw = _root_bytes(scope_fd, 65536)
        consumed = _root_bytes(consumed_fd, 256)
        catalog = _root_bytes(catalog_fd, 65536)
        binding_raw = _root_bytes(binding_fd, 65536)
        scope = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(Denied('invalid scope')))
        if not isinstance(scope, dict) or set(scope) != {
                'schema', 'request_contract',
                'generation', 'task_id', 'grant_sha256', 'catalog_sha256',
                'request_sha256', 'allowed_models', 'provider_binding_sha256'}:
            raise Denied('invalid scope')
        if type(scope['schema']) is not int or scope['schema'] != 2 or scope['request_contract'] != 'goose-turn-context-v1':
            raise Denied('invalid scope')
        generation, task = scope['generation'], scope['task_id']
        if not isinstance(generation, str) or not re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{26}', generation):
            raise Denied('invalid generation')
        if not isinstance(task, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', task):
            raise Denied('invalid task')
        for field in ('grant_sha256', 'catalog_sha256', 'request_sha256', 'provider_binding_sha256'):
            if not isinstance(scope[field], str) or not re.fullmatch(r'[0-9a-f]{64}', scope[field]):
                raise Denied('invalid digest')
        if hashlib.sha256(catalog).hexdigest() != scope['catalog_sha256']:
            raise Denied('catalog mismatch')
        if hashlib.sha256(binding_raw).hexdigest() != scope['provider_binding_sha256']:
            raise Denied('provider binding mismatch')
        binding = json.loads(binding_raw, object_pairs_hook=_unique)
        if not isinstance(binding, dict) or set(binding) != {'schema','container_id','image_id','pid','network_device','network_inode','sandbox_key','port'}:
            raise Denied('invalid provider binding')
        if (type(binding['schema']) is not int or binding['schema'] != 1
                or not isinstance(binding['container_id'],str) or not re.fullmatch(r'[0-9a-f]{64}',binding['container_id'])
                or not isinstance(binding['image_id'],str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',binding['image_id'])
                or any(type(binding[k]) is not int or binding[k]<=0 for k in ('pid','network_device','network_inode'))
                or type(binding['port']) is not int or binding['port'] != 8080
                or not isinstance(binding['sandbox_key'],str) or not re.fullmatch(r'/(?:var/run|run)/docker/netns/[0-9a-f]{12,64}',binding['sandbox_key'])):
            raise Denied('invalid provider binding')
        models = scope['allowed_models']
        if not isinstance(models, list) or not 1 <= len(models) <= 32 or len(set(models)) != len(models):
            raise Denied('invalid models')
        if any(not isinstance(m, str) or not 1 <= len(m) <= 256 or
               not all(33 <= ord(c) <= 126 for c in m) for m in models):
            raise Denied('invalid models')
        if consumed != (generation + '\n' + scope['grant_sha256'] + '\n').encode('ascii'):
            raise Denied('consumed binding mismatch')
        return scope, binding
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise Denied('authority unavailable') from None


def require_worker_peer(conn):
    # SO_PEERCRED is kernel supplied, never a caller-controlled header.
    if os.getuid() != 2000 or not hasattr(socket, 'SO_PEERCRED'):
        raise Denied('peer unavailable')
    try:
        _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    except (OSError, struct.error):
        raise Denied('peer unavailable') from None
    if uid != 2001:
        raise Denied('peer unavailable')


def verify_request(scope, raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 65536:
        raise Denied('request unavailable')
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(Denied('invalid request')))
        if not isinstance(value, dict) or set(value) != {'model', 'messages', 'tools', 'max_tokens', 'stream', 'stream_options'}:
            raise Denied('invalid request')
        tools = json.dumps(value['tools'], sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        approved_tools = json.dumps([WRITE_TOOL], sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        if (value['model'] != 'gpt-4o-mini' or tools != approved_tools
                or type(value['max_tokens']) is not int or value['max_tokens'] != 16384
                or value['stream'] is not True or not isinstance(value['stream_options'], dict)
                or set(value['stream_options']) != {'include_usage'}
                or value['stream_options']['include_usage'] is not True
                or not isinstance(value['messages'], list) or len(value['messages']) != 2):
            raise Denied('invalid request')
        for role, message in zip(('system', 'user'), value['messages']):
            if (not isinstance(message, dict) or set(message) != {'role', 'content'}
                    or message['role'] != role or not isinstance(message['content'], str)):
                raise Denied('invalid request')
            message['content'].encode('utf-8')
        if scope.get('schema') != 2 or scope.get('request_contract') != 'goose-turn-context-v1':
            raise Denied('request contract unavailable')
        text = value['messages'][1]['content']
        match = re.fullmatch(r'(?s)(.+)\n<turn-context>\n<current-time>([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \+00:00)</current-time>\n<working-directory>(/work/task)</working-directory>\n</turn-context>', text)
        if not match or any(tag in match.group(1) for tag in ('<turn-context>', '</turn-context>', '<current-time>', '<working-directory>')):
            raise Denied('turn context unavailable')
        timestamp = datetime.datetime.strptime(match.group(2), '%Y-%m-%d %H:%M:%S %z').timestamp()
        if abs(time.time() - timestamp) > 120:
            raise Denied('turn context unavailable')
        normalized = dict(value)
        normalized['messages'] = [value['messages'][0], {'role':'user','content':match.group(1)}]
        canonical = json.dumps(normalized, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        if hashlib.sha256(canonical).hexdigest() != scope['request_sha256']:
            raise Denied('request mismatch')
        return value
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise Denied('invalid request') from None


def validate_writer_arguments(raw):
    """Only the approved two-file typed request; never accept caller paths or commands."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 12288:
        raise Denied('writer request unavailable')
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(Denied('invalid request')))
        if not isinstance(value, dict) or set(value) != {'files'}:
            raise Denied('invalid request')
        files = value['files']
        if not isinstance(files, dict) or set(files) != {'hello.py', 'test_hello.py'}:
            raise Denied('invalid files')
        for content in files.values():
            if (not isinstance(content, str) or '\x00' in content or
                    not 0 < len(content.encode('utf-8')) <= 8192):
                raise Denied('invalid file')
        return value
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise Denied('invalid request') from None


class EffectFence:
    """Permanent, fsynced one-shot markers. Unknown outcomes are never retried."""
    def __init__(self, dirfd):
        st = os.fstat(dirfd)
        if not (stat.S_ISDIR(st.st_mode) and st.st_uid == 2000 and st.st_gid == 2000
                and stat.S_IMODE(st.st_mode) == 0o700):
            raise Denied('fence unavailable')
        self.dirfd = os.dup(dirfd)

    def begin(self, generation, kind, digest):
        if not re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{26}', generation) or kind not in ('inference0', 'writer', 'inference1') or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise Denied('invalid effect')
        name = generation + '.' + kind
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.dirfd)
            try:
                data = (generation + '\n' + kind + '\n' + digest + '\n').encode('ascii')
                if os.write(fd, data) != len(data):
                    raise Denied('fence incomplete')
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(self.dirfd)
        except OSError:
            raise Denied('effect unavailable') from None
