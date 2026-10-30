import errno
import hashlib
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock
p=pathlib.Path(__file__).with_name('nuc_pg_tree_harden.py')
spec=importlib.util.spec_from_file_location('pg_tree_harden',p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class TreeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)/'tree';self.root.mkdir();self.root.chmod(0o755)
  (self.root/'bin').mkdir();(self.root/'bin').chmod(0o775)
  (self.root/'bin'/'server').write_bytes(b'server');(self.root/'bin'/'server').chmod(0o755)
  os.symlink('server',self.root/'bin'/'link')
  self.entries={'format':1,'entries':[{'path':'bin','type':'directory','mode':'0o775'},
   {'path':'bin/server','type':'file','mode':'0o755','size':6,'sha256':hashlib.sha256(b'server').hexdigest()},
   {'path':'bin/link','type':'symlink','mode':oct(os.lstat(self.root/'bin/link').st_mode&0o7777),'target':'server'}]}
  self.patch=mock.patch.object(m.os,'getxattr',side_effect=OSError(errno.ENODATA,'none'),create=True);self.patch.start()
 def tearDown(self):self.patch.stop();self.tmp.cleanup()
 def check(self):return m.inspect_tree(self.root,self.entries,os.getuid(),os.getgid())
 def test_exact_tree_and_directory_identity(self):
  result=self.check();self.assertEqual([x['path'] for x in result['targets']],['bin']);self.assertEqual(result['targets'][0]['ino'],os.stat(self.root/'bin').st_ino)
 def test_extra_and_changed_file_denied(self):
  (self.root/'extra').touch()
  with self.assertRaisesRegex(RuntimeError,'entry set'):self.check()
  (self.root/'extra').unlink();(self.root/'bin/server').write_bytes(b'change')
  with self.assertRaisesRegex(RuntimeError,'digest'):self.check()
 def test_hardlink_and_symlink_swap_denied(self):
  os.link(self.root/'bin/server',self.root.parent/'other')
  with self.assertRaisesRegex(RuntimeError,'regular file'):self.check()
  (self.root.parent/'other').unlink();(self.root/'bin/link').unlink();os.symlink('/tmp',self.root/'bin/link')
  with self.assertRaisesRegex(RuntimeError,'symlink target'):self.check()
 def test_acl_or_unknown_failure_denied(self):
  for value in (b'acl',OSError(errno.EIO,'failure')):
   with mock.patch.object(m.os,'getxattr',side_effect=value if isinstance(value,Exception) else None,return_value=value,create=True):
    with self.assertRaises(RuntimeError):self.check()
 def test_traversal_and_changed_mode_denied(self):
  self.entries['entries'][0]['path']='../bin'
  with self.assertRaisesRegex(RuntimeError,'invalid path'):self.check()
  self.entries['entries'][0]['path']='bin';(self.root/'bin').chmod(0o777)
  with self.assertRaisesRegex(RuntimeError,'mode mismatch'):self.check()

class ApplyTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.tree=self.root/'pg';self.tree.mkdir();self.tree.chmod(0o755)
  self.etc=self.root/'etc';self.etc.mkdir();self.entries=[];self.targets=[]
  for index in range(62):
   name=f'd{index:02d}';p=self.tree/name;p.mkdir();p.chmod(0o775);st=p.stat()
   self.entries.append({'path':name,'type':'directory','mode':'0o775'})
   self.targets.append({'path':name,'dev':st.st_dev,'ino':st.st_ino})
  st=self.tree.stat();self.plan={'tree_dev':st.st_dev,'tree_ino':st.st_ino,'targets':self.targets}
  self.manifest={'format':1,'entries':self.entries};real_fstat=os.fstat
  def root_fstat(fd):
   st=real_fstat(fd); values=list(st);values[4]=0;values[5]=0;return os.stat_result(values)
  self.patches=[mock.patch.object(m,'PG',self.tree),mock.patch.object(m,'ETC',self.etc),
   mock.patch.object(m,'INTENT',self.etc/'intent'),mock.patch.object(m,'STEPS',self.etc/'steps'),
   mock.patch.object(m,'MANIFEST',self.etc/'manifest'),mock.patch.object(m,'DONE',self.etc/'done'),
   mock.patch.object(m,'preflight',return_value=self.plan),mock.patch.object(m,'source_manifest',side_effect=lambda: __import__('copy').deepcopy(self.manifest)),
   mock.patch.object(m.os,'fstat',side_effect=root_fstat),mock.patch.object(m.os,'getxattr',side_effect=OSError(errno.ENODATA,'none'),create=True)]
  for patch in self.patches:patch.start()
 def tearDown(self):
  for patch in reversed(self.patches):patch.stop()
  self.tmp.cleanup()
 def test_exact_success_records_each_change(self):
  m.apply(self.plan)
  self.assertTrue((self.etc/'intent').exists());self.assertEqual(len((self.etc/'steps').read_text().splitlines()),62)
  self.assertTrue((self.etc/'done').exists());self.assertTrue(all((self.tree/x['path']).stat().st_mode&0o777==0o755 for x in self.targets))
 def test_failure_retains_partial_without_completion(self):
  real=os.fchmod;calls=0
  def interrupted(fd,mode):
   nonlocal calls
   if mode==0o755:
    calls+=1
    if calls==2:raise OSError('injected failure')
   return real(fd,mode)
  with mock.patch.object(m.os,'fchmod',side_effect=interrupted):
   with self.assertRaises(OSError):m.apply(self.plan)
  self.assertTrue((self.etc/'intent').exists());self.assertEqual(len((self.etc/'steps').read_text().splitlines()),1)
  self.assertFalse((self.etc/'done').exists());self.assertEqual((self.tree/'d00').stat().st_mode&0o777,0o755)
  self.assertEqual((self.tree/'d01').stat().st_mode&0o777,0o775)

if __name__=='__main__':unittest.main()
