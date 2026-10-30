#!/usr/bin/python3
"""Fixed systemd namespace anchor; started only by reviewed root units.

Writes a single immutable observation and remains alive. Restart with a stale
observation fails closed; cleanup/reconciliation must be done explicitly.
"""
import json
import os
import pathlib
import signal
import stat
import sys

ROOT = pathlib.Path('/run/software-factory-goose')


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ('host', 'private'):
        raise RuntimeError('anchor identity or role mismatch')
    status = pathlib.Path('/proc/self/status').read_text().splitlines()
    fields = dict(line.split(':', 1) for line in status if ':' in line)
    if any(int(fields[name].strip(), 16) for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb')):
        raise RuntimeError('namespace anchor must have empty capabilities')
    rootfd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(rootfd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise RuntimeError('anchor directory untrusted')
        ns = os.stat('/proc/self/ns/net')
        data = json.dumps({'version': 1, 'role': sys.argv[1], 'pid': os.getpid(),
                           'uid': os.geteuid(), 'netns_dev': ns.st_dev, 'netns_ino': ns.st_ino},
                          sort_keys=True, separators=(',', ':')).encode() + b'\n'
        fd = os.open(sys.argv[1] + '-netns.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=rootfd)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as out:
                out.write(data); out.flush(); os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(rootfd)
    finally:
        os.close(rootfd)
    while True:
        signal.pause()


if __name__ == '__main__':
    main()
