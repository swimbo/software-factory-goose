import hashlib
import errno
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

p = pathlib.Path(__file__).with_name('nuc_pg_stage_install.py')
spec = importlib.util.spec_from_file_location('pg_stage_install', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class InstallTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.src = self.root / 'src'; self.src.mkdir()
        (self.src / 'bin').mkdir(); (self.src / 'bin').chmod(0o755)
        (self.src / 'bin' / 'binary').write_bytes(b'trusted')
        (self.src / 'bin' / 'binary').chmod(0o755)
        os.symlink('binary', self.src / 'bin' / 'link')
        self.manifest = self.root / 'manifest'
        entries = [{'path':'bin','type':'directory','mode':'0o755'},
                   {'path':'bin/binary','type':'file','mode':'0o755','size':7,
                    'sha256':hashlib.sha256(b'trusted').hexdigest()},
                   {'path':'bin/link','type':'symlink','mode':oct(os.lstat(self.src/'bin/link').st_mode & 0o7777),'target':'binary'}]
        raw = json.dumps({'format':1,'entries':entries},sort_keys=True,separators=(',',':')).encode()+b'\n'
        self.manifest.write_bytes(raw)
        self.patches = [mock.patch.object(m,'SOURCE',self.src), mock.patch.object(m,'MANIFEST',self.manifest),
                        mock.patch.object(m,'MANIFEST_SHA256',hashlib.sha256(raw).hexdigest()),
                        mock.patch.object(m,'DEST',self.root/'installed'), mock.patch.object(m.os,'geteuid',return_value=0)]
        original_lstat = os.lstat
        def root_parent(path, **kwargs):
            st = original_lstat(path, **kwargs)
            if pathlib.Path(path) == self.root:
                values = list(st); values[4] = 0
                return os.stat_result(values)
            return st
        self.patches.append(mock.patch.object(m.os,'lstat',side_effect=root_parent))
        self.patches.append(mock.patch.object(m.os,'getxattr',side_effect=OSError(errno.ENODATA, 'none'), create=True))
        for patch in self.patches: patch.start()
    def tearDown(self):
        for patch in reversed(self.patches): patch.stop()
        self.temp.cleanup()
    def test_acl_or_unknown_error_denied(self):
        for result in (b"acl", OSError(errno.EIO, "error")):
            with mock.patch.object(m.os, "getxattr", side_effect=result if isinstance(result, Exception) else None, return_value=result, create=True):
                with self.assertRaises(RuntimeError): m.apply()
                self.assertFalse((self.root/"installed").exists())
    def test_copy_and_collision(self):
        m.apply()
        self.assertEqual((self.root/'installed/bin/binary').read_bytes(), b'trusted')
        self.assertEqual(os.readlink(self.root/'installed/bin/link'), 'binary')
        with self.assertRaisesRegex(RuntimeError,'occupied'): m.apply()
    def test_extra_refused_before_destination(self):
        (self.src/'extra').touch()
        with self.assertRaisesRegex(RuntimeError,'differs'): m.apply()
        self.assertFalse((self.root/'installed').exists())
    def test_changed_file_refuses_and_retains_partial(self):
        (self.src/'bin/binary').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'digest mismatch'): m.apply()
        self.assertTrue((self.root/'installed').is_dir())
    def test_hardlinked_source_refused(self):
        os.link(self.src/'bin/binary', self.root/'external-link')
        with self.assertRaisesRegex(RuntimeError, 'source file mismatch'): m.apply()
        self.assertTrue((self.root/'installed').is_dir())
    def test_symlinked_source_ancestor_refused(self):
        (self.src/'bin/binary').unlink(); (self.src/'bin/link').unlink(); (self.src/'bin').rmdir()
        other = self.root/'outside'; other.mkdir(); os.symlink(other,self.src/'bin')
        with self.assertRaises(RuntimeError): m.apply()
        self.assertFalse((self.root/'installed').exists())

if __name__ == '__main__': unittest.main()
