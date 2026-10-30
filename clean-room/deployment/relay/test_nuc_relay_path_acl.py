import errno,os,stat,types,unittest
from unittest.mock import patch
from nuc_relay_authority import Denied,_no_acl_pinned_dir
from nuc_relay_guard import RootGuard
from nuc_relay_writer import RootWriter
G='01ARZ3NDEKTSV4RRFFQ69G5FAV'
class Paths(unittest.TestCase):
 def test_path_acl_checks_access_and_default_and_denies_unknown(self):
  seen=[]
  def absent(path,name):seen.append((path,name));raise OSError(errno.ENODATA,'none')
  with patch('nuc_relay_authority.sys.platform','linux'),patch('nuc_relay_authority.os.getxattr',side_effect=absent,create=True):_no_acl_pinned_dir(42)
  self.assertEqual(seen,[('/proc/self/fd/42','system.posix_acl_access'),('/proc/self/fd/42','system.posix_acl_default')])
  for effect in (b'acl',OSError(errno.EACCES,'denied')):
   with patch('nuc_relay_authority.sys.platform','linux'),patch('nuc_relay_authority.os.getxattr',side_effect=effect if isinstance(effect,Exception) else None,return_value=effect,create=True):
    with self.assertRaises(Denied):_no_acl_pinned_dir(42)
 def test_guard_and_writer_traverse_by_pinned_path_descriptors(self):
  scope={'generation':G,'grant_sha256':'a'*64,'catalog_sha256':'b'*64,'provider_binding_sha256':'c'*64};binding={'network_device':1,'network_inode':2}
  for module,obj in [('nuc_relay_guard',RootGuard(scope,binding)),('nuc_relay_writer',RootWriter(scope))]:
   directory=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o710)
   endpoint=types.SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=2000,st_nlink=1)
   with patch(module+'._open_path_dir',side_effect=[10,11,12,13]) as op,patch(module+'._no_acl_pinned_dir') as acl,patch(module+'.os.close'),patch(module+'.os.fstat',return_value=directory),patch(module+'.os.stat',return_value=endpoint):
    obj._verify_path();self.assertEqual(op.call_count,4);self.assertEqual(acl.call_count,3)
if __name__=='__main__':unittest.main()
