import hashlib,os,pathlib,stat,tempfile,types,unittest
from unittest import mock
import nuc_registry_pinned_binary as pinned
class StreamedBinaryTests(unittest.TestCase):
 def test_streams_bounded_chunks_and_checks_exact_digest(self):
  with tempfile.TemporaryDirectory() as tmp:
   path=pathlib.Path(tmp)/'binary';data=b'x'*(pinned.CHUNK*2+17);path.write_bytes(data);path.chmod(0o755);realstat=os.fstat;realread=os.read;requests=[]
   def fake_stat(fd):
    s=realstat(fd);return types.SimpleNamespace(st_mode=s.st_mode,st_uid=0,st_gid=0,st_nlink=s.st_nlink,st_size=s.st_size,st_dev=s.st_dev,st_ino=s.st_ino,st_mtime_ns=s.st_mtime_ns,st_ctime_ns=s.st_ctime_ns)
   def read(fd,n):requests.append(n);return realread(fd,n)
   with mock.patch.object(pinned.os,'fstat',side_effect=fake_stat),mock.patch.object(pinned.os,'read',side_effect=read),mock.patch.object(pinned.old,'noacl'):
    result=pinned.verify(path,hashlib.sha256(data).hexdigest());self.assertEqual(result['size'],len(data));self.assertTrue(requests and max(requests)<=pinned.CHUNK)
    with self.assertRaisesRegex(RuntimeError,'binary changed'):pinned.verify(path,'0'*64)
    with self.assertRaisesRegex(RuntimeError,'metadata unavailable'):pinned.verify(path,hashlib.sha256(data).hexdigest(),4)
 def test_refuses_bound_above_cap(self):
  with self.assertRaisesRegex(RuntimeError,'pin unavailable'):pinned.verify('/not/read','a'*64,pinned.MAX_BYTES+1)
if __name__=='__main__':unittest.main()
