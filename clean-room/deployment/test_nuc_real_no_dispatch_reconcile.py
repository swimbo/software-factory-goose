import os,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import nuc_real_no_dispatch_reconcile as n
class Tests(unittest.TestCase):
 def test_read_accepts_exact_manifest_without_optional_hash(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'manifest';p.write_bytes(b'{"schema":1}');p.chmod(0o600);actual=os.fstat
   def fake(fd):
    s=actual(fd);return types.SimpleNamespace(st_mode=s.st_mode,st_uid=1234,st_gid=1234,st_nlink=s.st_nlink,st_size=s.st_size)
   with patch.object(n.os,'fstat',side_effect=fake),patch.object(n,'noacl'):
    self.assertEqual(n.read(p,1234,0o600,limit=65536),b'{"schema":1}')
 def test_existing_or_symlink_launch_lock_refuses_no_dispatch(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(n,'STATE',Path(tmp)),patch.object(n,'ROOT',Path(tmp)):
   n.original_fence();(Path(tmp)/(n.G+'.lock')).symlink_to('missing')
   with self.assertRaises(RuntimeError):n.original_fence()
 def test_changed_review_fails_before_stop(self):
  with patch.object(n,'make_plan',return_value={'evidence':'changed'}),patch.object(n,'store') as store,patch.object(n,'ctl') as ctl:
   with self.assertRaises(RuntimeError):n.apply(n.Host('x'),{'evidence':'reviewed'})
   store.assert_not_called();ctl.assert_not_called()
 def test_live_driver_or_changed_invocation_refuses(self):
  def props(unit,key):
   expected={'LoadState':'loaded','ActiveState':'failed','Result':'exit-code','ExecMainStatus':'1','MainPID':'0','ControlGroup':'','Job':'','Names':n.DRIVER,'Transient':'yes','FragmentPath':'/run/systemd/transient/'+n.DRIVER,'DropInPaths':'','InvocationID':n.INVOCATION,'User':'root','Group':'root','NoNewPrivileges':'yes','CapabilityBoundingSet':''}
   expected['MainPID']='17';return expected[key]
  with patch.object(n,'prop',side_effect=props):
   with self.assertRaises(RuntimeError):n.driver()
if __name__=='__main__':unittest.main()
