import hashlib,pathlib,tempfile,unittest
from unittest import mock
import nuc_registry_v5_guarded_install as install
class GuardedInstall(unittest.TestCase):
 def test_inactive_services_and_sockets_use_available_properties(self):
  units={'test.socket':b'socket','test.service':b'service'}
  def ctl(*args):
   unit=args[1];key=args[3]
   if key=='MainPID':
    self.assertTrue(unit.endswith('.service'));return '0'
   return {'Names':unit,'LoadState':'loaded','ActiveState':'inactive','Job':'','FragmentPath':str(install.old.UNIT/unit),'DropInPaths':''}[key]
  with mock.patch.object(install,'units',return_value=units),mock.patch.object(install.old,'read'),mock.patch.object(install.old,'ctl',side_effect=ctl):install.inactive()
  with mock.patch.object(install,'units',return_value=units),mock.patch.object(install.old,'read'),mock.patch.object(install.old,'ctl',side_effect=lambda *a:'active' if a[3]=='ActiveState' else ctl(*a)):
   with self.assertRaisesRegex(RuntimeError,'not inactive'):install.inactive()
 def test_copy_is_streamed_create_only_and_exact(self):
  with tempfile.TemporaryDirectory() as td:
   src=pathlib.Path(td)/'source';dst=pathlib.Path(td)/'copy';data=b'public binary bytes'*10000;src.write_bytes(data);pin=hashlib.sha256(data).hexdigest();identity={'bytes':len(data)}
   with mock.patch.object(install,'identity',return_value=identity),mock.patch.object(install.old,'noacl'),mock.patch.object(install.old,'syncdir'):
    install.copy(src,1000,0o700,pin,dst);self.assertEqual(dst.read_bytes(),data);self.assertEqual(dst.stat().st_mode&0o777,0o755)
    with self.assertRaises(FileExistsError):install.copy(src,1000,0o700,pin,dst)
 def test_uncertain_copy_retains_intent_without_replacing_or_completing(self):
  with mock.patch.object(install,'plan',return_value={'approved':True}),mock.patch.object(install.old,'store') as store,mock.patch.object(install,'copy',side_effect=RuntimeError('copy uncertain')),mock.patch.object(install.os,'replace') as replace:
   with self.assertRaisesRegex(RuntimeError,'copy uncertain'):install.apply({'approved':True})
   self.assertEqual(store.call_count,1);self.assertEqual(store.call_args.args[0],install.START);replace.assert_not_called()
