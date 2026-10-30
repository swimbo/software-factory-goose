#!/usr/bin/env python3
"""Copy one reviewed NUC PostgreSQL stage, with no service or database changes.

This is a narrow installer prerequisite, not the private runtime deployment. A failed
copy is retained for inspection and never overwritten or automatically removed.
"""
import hashlib
import errno
import contextlib
import json
import os
import pathlib
import stat
import sys

SOURCE = pathlib.Path('/tmp/sfactory-pg1711-build.vfNv9w4h/stage/usr/local/libexec/software-factory-goose/postgresql17')
MANIFEST = pathlib.Path('/tmp/sfactory-pg1711-build.vfNv9w4h/staged-tree.json')
MANIFEST_SHA256 = '39216b7ac1e082074b9e6098e5a3c94a0d706a1910cc302b9df0eddd4d9d23e5'
DEST = pathlib.Path('/usr/local/libexec/software-factory-goose/postgresql17')


def fail(reason):
    raise RuntimeError(reason)


def manifest():
    fd = os.open(MANIFEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 2_000_000:
            fail('manifest unavailable')
        raw = stream.read(2_000_001)
    if len(raw) > 2_000_000 or hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        fail('manifest mismatch')
    data = json.loads(raw)
    if set(data) != {'format', 'entries'} or data['format'] != 1:
        fail('manifest format mismatch')
    return data['entries']


@contextlib.contextmanager
def source_parent(root_fd, relative):
    parts = relative.split('/')
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, parts[-1]
    finally:
        os.close(fd)


def apply():
    if os.geteuid() != 0:
        fail('root required')
    parent = DEST.parent
    for ancestor in (pathlib.Path('/'), pathlib.Path('/usr'), pathlib.Path('/usr/local'),
                     pathlib.Path('/usr/local/libexec'), parent):
        info = os.lstat(ancestor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            fail('destination ancestry untrusted')
        for attribute in ('system.posix_acl_access', 'system.posix_acl_default'):
            try:
                os.getxattr(ancestor, attribute, follow_symlinks=False)
            except OSError as error:
                if error.errno != errno.ENODATA:
                    fail('destination ACL could not be checked')
            else:
                fail('destination ACL forbidden')
    info = os.lstat(parent)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        fail('destination parent untrusted')
    if os.path.lexists(DEST):
        fail('destination occupied; retain and reconcile')
    entries = manifest()
    # A separately rooted privileged reviewer must approve this exact manifest.
    # Build copies are hashed as read, and source regular files are never followed.
    paths = set()
    for entry in entries:
        rel = entry['path']; parts = pathlib.PurePosixPath(rel).parts
        if not parts or any(p in ('', '.', '..') for p in rel.split('/')) or rel.startswith('/') or rel in paths:
            fail('invalid manifest path')
        paths.add(rel)
        if len(parts) > 1 and '/'.join(parts[:-1]) not in paths:
            fail('manifest parent missing or out of order')
        if entry['type'] not in ('directory', 'file', 'symlink'):
            fail('unsupported entry')
    source_fd = os.open(SOURCE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        found = set()
        for root, dirs, files, _ in os.fwalk('.', dir_fd=source_fd, follow_symlinks=False):
            prefix = '' if root == '.' else root.removeprefix('./') + '/'
            found.update(prefix + name for name in dirs + files)
        if found != paths:
            fail('source tree differs from manifest')
        os.mkdir(DEST, 0o755)
        os.chmod(DEST, 0o755)
        for entry in entries:
            with source_parent(source_fd, entry['path']) as (parent_fd, name):
                dst = DEST / entry['path']
                kind, mode = entry['type'], int(entry['mode'], 8)
                st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_IMODE(st.st_mode) != mode:
                    fail('source mode mismatch')
                if kind == 'directory':
                    if not stat.S_ISDIR(st.st_mode): fail('source type mismatch')
                    os.mkdir(dst, mode)
                    os.chmod(dst, mode)
                elif kind == 'symlink':
                    if not stat.S_ISLNK(st.st_mode) or os.readlink(name, dir_fd=parent_fd) != entry['target']:
                        fail('source symlink mismatch')
                    target = entry['target']
                    if not target or '/' in target or target in ('.', '..'): fail('unsafe symlink')
                    os.symlink(target, dst)
                else:
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size != entry['size']:
                        fail('source file mismatch')
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
                    try:
                        actual = os.fstat(fd)
                        if (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mode, actual.st_nlink) != (st.st_dev, st.st_ino, st.st_size, st.st_mode, st.st_nlink):
                            fail('source file changed')
                        out = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                        try:
                            digest = hashlib.sha256(); total = 0
                            while True:
                                data = os.read(fd, 65536)
                                if not data: break
                                total += len(data)
                                if total > entry['size']: fail('source file grew')
                                digest.update(data)
                                view = memoryview(data)
                                while view:
                                    n = os.write(out, view)
                                    if n <= 0: fail('short write')
                                    view = view[n:]
                            if total != entry['size'] or digest.hexdigest() != entry['sha256']:
                                fail('source digest mismatch')
                            os.fchmod(out, mode); os.fsync(out)
                        finally: os.close(out)
                    finally: os.close(fd)
    finally:
        os.close(source_fd)
    # Persist all directories bottom-up including destination parent.
    for root, dirs, _ in os.walk(DEST, topdown=False, followlinks=False):
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


if __name__ == '__main__':
    if sys.argv != [sys.argv[0], '--apply']:
        raise SystemExit('usage: nuc_pg_stage_install.py --apply')
    apply()
