"""Public-only systemd OpenFile and host-netns identity canary; never reads credentials."""
import fcntl
import errno
import hashlib
import json
import os
import stat
import sys

PUBLIC = b'SFACTORY-PUBLIC-OPENFILE-20261030\n'

def main():
    if sys.platform != 'linux' or os.getuid() != 2000 or os.environ.get('LISTEN_PID') != str(os.getpid()):
        raise RuntimeError('canary unavailable')
    names = os.environ.get('LISTEN_FDNAMES', '').split(':')
    if os.environ.get('LISTEN_FDS') != '2' or len(names) != 2 or set(names) != {'public','expected'}:
        raise RuntimeError('canary unavailable')
    fds = {name:3 + index for index,name in enumerate(names)}
    contents = {}
    for name in ('public','expected'):
        fd=fds[name];s=os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0
                or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1 or not 0 < s.st_size <= 256
                or fcntl.fcntl(fd,fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY):
            raise RuntimeError('canary unavailable')
        try:os.getxattr(fd,'system.posix_acl_access')
        except OSError as error:
            if error.errno != errno.ENODATA:raise RuntimeError('canary unavailable') from None
        else:raise RuntimeError('canary unavailable')
        contents[name]=os.pread(fd,257,0)
        if len(contents[name]) != s.st_size:raise RuntimeError('canary unavailable')
    if contents['public'] != PUBLIC:raise RuntimeError('canary unavailable')
    expected=json.loads(contents['expected'])
    if (not isinstance(expected,dict) or set(expected)!={'network_device','network_inode'}
            or any(type(expected[k]) is not int or expected[k]<=0 for k in expected)):
        raise RuntimeError('canary unavailable')
    network=os.stat('/proc/self/ns/net')
    if (network.st_dev,network.st_ino)!=(expected['network_device'],expected['network_inode']):
        raise RuntimeError('canary unavailable')
    print(json.dumps({'public_sha256':hashlib.sha256(PUBLIC).hexdigest(),
                      'uid':os.getuid(),'root_readonly_fd':True,'network_identity_matched':True},sort_keys=True))

if __name__ == '__main__':main()
