import contextlib,errno,json,stat,types,unittest
from unittest import mock
import nuc_registry_restore_verify as verify
class RestoreVerifyTests(unittest.TestCase):
 def test_mismatched_restored_state_never_publishes_success(self):
  observed=[];baseline={'histories':[{'service':'ClaimLeaseJournal','key':'01M65RMR3FE6FQTFRBHERRHXRG','rows':[]}]};raw=json.dumps(baseline).encode()
  plan={'preservation':{},'private_namespace':[1,2],'host_namespace':[1,3],'targets':[],'baseline_sha256':'a'*64}
  @contextlib.contextmanager
  def locked():yield
  sock=types.SimpleNamespace(st_mode=stat.S_IFSOCK|0o700,st_uid=2004,st_gid=2004,st_nlink=1)
  def attr(*a,**k):raise OSError(errno.ENODATA,'none')
  with mock.patch.object(verify.backup,'locked',locked),mock.patch.object(verify,'plan_locked',return_value=plan),mock.patch.object(verify.old,'store',side_effect=lambda p,*a:observed.append(p)),mock.patch.object(verify.old,'ctl'),mock.patch.object(verify,'identity',return_value={'unit':'fixture'}),mock.patch.object(verify,'namespace',return_value=[2,4]),mock.patch.object(verify.os.path,'lexists',return_value=True),mock.patch.object(verify.os,'lstat',return_value=sock),mock.patch.object(verify.os,'getxattr',side_effect=attr,create=True),mock.patch.object(verify.history,'invoke',return_value={'histories':[]}),mock.patch.object(verify.old,'read',return_value=raw),mock.patch.object(verify.retirement,'capture_transport'),mock.patch.object(verify.retirement,'terminal') as terminal:
   with self.assertRaisesRegex(RuntimeError,'restored state differs'):verify.apply(plan)
  self.assertEqual(observed,[verify.START]);terminal.assert_not_called()
if __name__=='__main__':unittest.main()
