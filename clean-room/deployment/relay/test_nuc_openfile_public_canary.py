import contextlib
import errno
import io
import json
import os
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import nuc_openfile_public_canary as c

class PublicCanary(unittest.TestCase):
    def test_named_fds_and_network_match(self):
        expected=b'{"network_device":1,"network_inode":2}'
        data={3:expected,4:c.PUBLIC}
        def fake_stat(fd):return SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_gid=0,st_nlink=1,st_size=len(data[fd]))
        env={'LISTEN_PID':str(os.getpid()),'LISTEN_FDS':'2','LISTEN_FDNAMES':'expected:public'}
        with patch.dict(os.environ,env,clear=True),patch.object(c.sys,'platform','linux'),patch.object(c.os,'getuid',return_value=2000),patch.object(c.os,'fstat',side_effect=fake_stat),patch.object(c.os,'pread',side_effect=lambda fd,n,o:data[fd]),patch.object(c.os,'stat',return_value=SimpleNamespace(st_dev=1,st_ino=2)),patch.object(c.os,'getxattr',side_effect=OSError(errno.ENODATA,'absent'),create=True),patch.object(c.fcntl,'fcntl',return_value=os.O_RDONLY),contextlib.redirect_stdout(io.StringIO()) as out:
            c.main();self.assertTrue(json.loads(out.getvalue())['network_identity_matched'])
    def test_wrong_process_or_missing_descriptors_denied(self):
        with patch.dict(os.environ,{'LISTEN_PID':'-1'},clear=True),patch.object(c.os,'getuid',return_value=2000):
            with self.assertRaises(RuntimeError):c.main()

if __name__=='__main__':unittest.main()
