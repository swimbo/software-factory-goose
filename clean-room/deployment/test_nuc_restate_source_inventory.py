import os,pathlib,tempfile,types,unittest
from unittest import mock
import nuc_restate_source_inventory as inventory
class SourceInventoryTests(unittest.TestCase):
 def test_live_size_and_destination_capacity_bound(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);source=root/'source';dest=root/'dest';source.mkdir(mode=0o755);source.chmod(0o755);dest.mkdir(mode=0o711);dest.chmod(0o711);(source/'data').write_bytes(b'12345');destination_ino=dest.stat().st_ino;real_fstat=os.fstat;real_stat=os.stat;filesystem_fds=[]
   def owned(s):
    return types.SimpleNamespace(**{k:((0 if s.st_ino==destination_ino else 2004) if k in ('st_uid','st_gid') else getattr(s,k)) for k in ('st_mode','st_uid','st_gid','st_nlink','st_size','st_dev','st_ino','st_mtime_ns','st_ctime_ns')})
   def fs(fd):filesystem_fds.append(real_fstat(fd).st_ino);return types.SimpleNamespace(f_bavail=10*1024**3,f_frsize=1)
   with mock.patch.object(inventory.os,'fstat',side_effect=lambda fd:owned(real_fstat(fd))),mock.patch.object(inventory.os,'stat',side_effect=lambda *a,**k:owned(real_stat(*a,**k))),mock.patch.object(inventory.tree,'no_acl'),mock.patch.object(inventory.old,'noacl'),mock.patch.object(inventory.old,'directory'),mock.patch.object(inventory.os,'fstatvfs',side_effect=fs):
    result=inventory.inspect(source,dest);self.assertEqual(result['logical_bytes'],5);self.assertEqual(result['required_bytes'],inventory.RESERVE+20);self.assertTrue(result['snapshot_is_live']);self.assertEqual(filesystem_fds,[destination_ino]);inventory.old.directory.assert_called_with(source.parent,2004,2004,0o700)
    source.chmod(0o700)
    with self.assertRaisesRegex(RuntimeError,'Restate source unavailable'):inventory.inspect(source,dest)
    source.chmod(0o755)
   with mock.patch.object(inventory.os,'fstat',side_effect=lambda fd:owned(real_fstat(fd))),mock.patch.object(inventory.os,'stat',side_effect=lambda *a,**k:owned(real_stat(*a,**k))),mock.patch.object(inventory.tree,'no_acl'),mock.patch.object(inventory.old,'noacl'),mock.patch.object(inventory.old,'directory'),mock.patch.object(inventory.os,'fstatvfs',return_value=types.SimpleNamespace(f_bavail=1,f_frsize=1)):
    with self.assertRaisesRegex(RuntimeError,'insufficient'):inventory.inspect(source,dest)
if __name__=='__main__':unittest.main()
