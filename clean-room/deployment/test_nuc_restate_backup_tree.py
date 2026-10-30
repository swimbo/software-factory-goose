import os,pathlib,sys,tempfile,unittest,types
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_restate_backup_tree as tree

class BackupTreeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();root=pathlib.Path(self.tmp.name);self.src=root/'source';self.dst=root/'backup';self.src.mkdir();self.dst.mkdir();self.s=os.open(self.src,os.O_RDONLY|os.O_DIRECTORY);self.d=os.open(self.dst,os.O_RDONLY|os.O_DIRECTORY);self.acl=mock.patch.object(tree,'no_acl');self.acl.start();self.addCleanup(self.acl.stop);self.addCleanup(os.close,self.s);self.addCleanup(os.close,self.d);self.addCleanup(self.tmp.cleanup)
 def copy(self):return tree.copy_tree(self.s,self.d,os.getuid(),os.getgid())
 def test_copies_exact_bytes_and_metadata_with_manifest(self):
  (self.src/'nested').mkdir();(self.src/'nested'/'data').write_bytes(b'journal bytes');(self.src/'nested'/'data').chmod(0o600)
  result=self.copy();self.assertEqual((result['files'],result['bytes']),(1,13));self.assertEqual((self.dst/'nested'/'data').read_bytes(),b'journal bytes');self.assertEqual((self.dst/'nested'/'data').stat().st_mode&0o777,0o600);self.assertEqual([x['path'] for x in result['entries']],['nested','nested/data'])
 def test_restore_copy_preserves_manifest_and_bytes(self):
  (self.src/'dir').mkdir();(self.src/'dir'/'journal').write_bytes(b'abc');first=self.copy()
  restore=pathlib.Path(self.tmp.name)/'restored';restore.mkdir();r=os.open(restore,os.O_RDONLY|os.O_DIRECTORY)
  try:second=tree.copy_tree(self.d,r,os.getuid(),os.getgid())
  finally:os.close(r)
  self.assertEqual(second,first);self.assertEqual((restore/'dir'/'journal').read_bytes(),b'abc')
 def test_symlink_and_hardlink_denied(self):
  (self.src/'outside').symlink_to('/etc/passwd')
  with self.assertRaisesRegex(RuntimeError,'unsupported source'):self.copy()
  (self.src/'outside').unlink();(self.src/'original').write_bytes(b'x');os.link(self.src/'original',self.src/'link')
  with self.assertRaisesRegex(RuntimeError,'link invalid'):self.copy()
 def test_cross_device_source_is_refused(self):
  (self.src/'data').write_bytes(b'x');real=tree.os.stat
  def changed(name,*args,**kwargs):
   result=real(name,*args,**kwargs)
   if name=='data':
    fields={key:getattr(result,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')};fields['st_dev']+=1;return types.SimpleNamespace(**fields)
   return result
  with mock.patch.object(tree.os,'stat',side_effect=changed),self.assertRaisesRegex(RuntimeError,'filesystem boundary'):self.copy()
  self.assertFalse((self.dst/'data').exists())
 def test_corrupted_destination_fails_verification(self):
  (self.src/'data').write_bytes(b'abc');real=tree.os.write
  def corrupt(fd,data):return real(fd,b'X'+bytes(data)[1:])
  with mock.patch.object(tree.os,'write',side_effect=corrupt),self.assertRaisesRegex(RuntimeError,'destination verification'):self.copy()
 def test_nonempty_destination_denied_without_overwrite(self):
  (self.dst/'existing').write_text('retain')
  with self.assertRaisesRegex(RuntimeError,'destination must be empty'):self.copy()
  self.assertEqual((self.dst/'existing').read_text(),'retain')
 def test_directory_entry_limit_is_bounded(self):
  (self.src/'one').mkdir();(self.src/'two').mkdir()
  with mock.patch.object(tree,'MAX_FILES',1),self.assertRaisesRegex(RuntimeError,'entry bound'):self.copy()
 def test_byte_limit_prevents_writing_oversized_file(self):
  (self.src/'data').write_bytes(b'1234')
  with mock.patch.object(tree,'MAX_BYTES',3),self.assertRaisesRegex(RuntimeError,'bound'):self.copy()
  self.assertFalse((self.dst/'data').exists())
if __name__=='__main__':unittest.main()
